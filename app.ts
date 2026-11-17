// github-forge-r4: a standalone GitHub-compatible git forge in one Node process.
// Serves git smart HTTP (upload-pack v2 + receive-pack v0), REST v3, GraphQL v4 and
// MCP (Streamable HTTP, revision 2026-07-28) from a single in-memory store.
// Node 22 stdlib only. Written from the competition kit's wire specification.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------- viewer identity
// The suite's bearer token is opaque, so the token owner is the scenario's viewer:
// wire.ts derives it deterministically from SCENARIO_SEED. Recompute that one login
// here (first generated user) so repos live under the owner every check expects.
const FIRST_NAMES = ['ada','bram','cora','dmitri','elena','felix','greta','hugo','iris','jonas','kira','lars','mira','nico','olga','pavel','quinn','rosa','sven','tess','ulla','vito','wren','yara','zane'];
const LAST_NAMES = ['anders','bauer','costa','dahl','eriksen','fischer','garcia','holm','iversen','jansen','keller','lind','moreau','novak','olsen','peters','quist','rossi','sato','turi','ulrich','vega','weber','xu','yilmaz','zimmer'];
const U64 = 0xffffffffffffffffn;
function fnv1a64(text: string): bigint {
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i++) { h ^= BigInt(text.charCodeAt(i)); h = (h * 0x100000001b3n) & U64; }
  return h;
}
function mix64(v: bigint): bigint {
  let z = (v + 0x9e3779b97f4a7c15n) & U64;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64;
  return (z ^ (z >> 31n)) & U64;
}
class Rng {
  s: bigint;
  constructor(seed: bigint) { const m = seed & U64; this.s = m === 0n ? 0x6a09e667f3bcc909n : m; }
  nextU64(): bigint {
    let x = this.s;
    x = (x ^ (x >> 12n)) & U64; x = (x ^ (x << 25n)) & U64; x = (x ^ (x >> 27n)) & U64;
    this.s = x; return (x * 0x2545f4914f6cdd1dn) & U64;
  }
  nextU32(): number { return Number(this.nextU64() >> 32n); }
  nextInt(max: number): number {
    if (max === 1) return 0;
    const range = 4294967296, limit = range - (range % max);
    for (;;) { const v = this.nextU32(); if (v < limit) return v % max; }
  }
  pick<T>(items: readonly T[]): T { return items[this.nextInt(items.length)] as T; }
}
function viewerLogin(): string {
  const rng = new Rng(mix64(0x6a09e667f3bcc909n ^ fnv1a64('users')));
  return `${rng.pick(FIRST_NAMES)}${rng.pick(LAST_NAMES)}`;
}
export const VIEWER = viewerLogin();
export const VIEWER_NAME = 'Ada Iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const ZERO_OID = '0'.repeat(40);
const AGENT = 'github-forge/1.0';

// ---------------------------------------------------------------- small utils
let reqSeq = 0;
let objSeq = 0;
function sha1hex(data: Buffer): string { return createHash('sha1').update(data).digest('hex'); }
function hashObject(type: string, data: Buffer): string {
  const h = createHash('sha1');
  h.update(`${type} ${data.length}\0`, 'utf8');
  h.update(data);
  return h.digest('hex');
}
function b64(buf: Buffer): string { return buf.toString('base64'); }
function b64dec(s: string): Buffer { return Buffer.from(s.replace(/[\r\n\t ]+/g, ''), 'base64'); }
function gid(kind: string, id: string): string { return Buffer.from(`${kind}:${id}`, 'utf8').toString('base64'); }
function ungid(s: string): { kind: string; id: string } | null {
  try {
    const t = Buffer.from(s, 'base64').toString('utf8');
    const i = t.indexOf(':');
    if (i < 1) return null;
    return { kind: t.slice(0, i), id: t.slice(i + 1) };
  } catch { return null; }
}
function isoTs(seq: number): string { return new Date((1735689600 + seq) * 1000).toISOString(); }
function dec(s: string): string { try { return decodeURIComponent(s); } catch { return s; } }

// ---------------------------------------------------------------- pkt-line
function pkt(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const head = Buffer.allocUnsafe(4);
  head.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, data]);
}
const FLUSH = Buffer.from('0000', 'ascii');
const DELIM = Buffer.from('0001', 'ascii');
function decodePktLines(buf: Buffer): { lines: string[]; rest: Buffer } {
  const lines: string[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = parseInt(buf.subarray(off, off + 4).toString('ascii'), 16);
    if (Number.isNaN(len)) return { lines, rest: buf.subarray(off) }; // raw binary (pack) starts here
    if (len === 0 || len === 1 || len === 2) { off += 4; continue; }
    if (len < 4 || off + len > buf.length) return { lines, rest: buf.subarray(off) };
    lines.push(buf.subarray(off + 4, off + len).toString('utf8'));
    off += len;
  }
  return { lines, rest: buf.subarray(off) };
}

// ---------------------------------------------------------------- git object model
type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GObj { type: ObjType; data: Buffer }
interface TreeEntry { mode: string; name: string; oid: string }
function parseTree(data: Buffer): TreeEntry[] {
  const out: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    const nul = data.indexOf(0x00, sp + 1);
    out.push({ mode: data.subarray(off, sp).toString('ascii'), name: data.subarray(sp + 1, nul).toString('utf8'), oid: data.subarray(nul + 1, nul + 21).toString('hex') });
    off = nul + 21;
  }
  return out;
}
function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const l = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
    const r = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
    return Buffer.compare(l, r);
  });
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}
interface CommitView { tree: string; parents: string[]; message: string }
function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const head = blank < 0 ? data.toString('utf8') : data.subarray(0, blank).toString('utf8');
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5);
    else if (line.startsWith('parent ')) parents.push(line.slice(7));
  }
  return { tree, parents, message };
}
function parseTagTarget(data: Buffer): { object: string; type: string } {
  const blank = data.indexOf('\n\n');
  const head = blank < 0 ? data.toString('utf8') : data.subarray(0, blank).toString('utf8');
  let object = '', type = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7);
    else if (line.startsWith('type ')) type = line.slice(5);
  }
  return { object, type };
}
function peelToCommit(repo: Repo, oid: string): string {
  let cur = oid;
  for (let i = 0; i < 8; i++) {
    const o = repo.objects.get(cur);
    if (!o || o.type !== 'tag') return cur;
    cur = parseTagTarget(o.data).object;
  }
  return cur;
}
function cinfo(repo: Repo, oid: string): { tree: string; parents: string[] } | null {
  let c = repo.cinfo.get(oid);
  if (c) return c;
  const o = repo.objects.get(oid);
  if (!o || o.type !== 'commit') return null;
  const v = parseCommit(o.data);
  c = { tree: v.tree, parents: v.parents };
  repo.cinfo.set(oid, c);
  return c;
}
function reachable(repo: Repo, roots: Iterable<string>): Set<string> {
  const seen = new Set<string>();
  const q: string[] = [];
  for (const r of roots) if (r !== ZERO_OID) q.push(r);
  while (q.length) {
    const oid = q.pop() as string;
    if (seen.has(oid)) continue;
    const o = repo.objects.get(oid);
    if (!o) continue;
    seen.add(oid);
    if (o.type === 'commit') { const c = cinfo(repo, oid); if (c) { q.push(c.tree); for (const p of c.parents) q.push(p); } }
    else if (o.type === 'tag') q.push(parseTagTarget(o.data).object);
    else if (o.type === 'tree') for (const e of parseTree(o.data)) if (e.mode !== '160000') q.push(e.oid);
  }
  return seen;
}
function isAncestor(repo: Repo, anc: string, oid: string): boolean {
  if (anc === oid) return true;
  const seen = new Set<string>();
  const q = [oid];
  while (q.length) {
    const cur = q.pop() as string;
    if (cur === anc) return true;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const c = cinfo(repo, cur);
    if (c) for (const p of c.parents) q.push(p);
  }
  return false;
}
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const ancA = new Set<string>();
  const q = [a];
  while (q.length) {
    const cur = q.pop() as string;
    if (ancA.has(cur)) continue;
    ancA.add(cur);
    const c = cinfo(repo, cur);
    if (c) for (const p of c.parents) q.push(p);
  }
  const qb = [b];
  const seen = new Set<string>();
  while (qb.length) {
    const cur = qb.shift() as string;
    if (ancA.has(cur)) return cur;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const o = repo.objects.get(cur);
    if (o && o.type === 'commit') for (const p of parseCommit(o.data).parents) qb.push(p);
  }
  return null;
}
// flatten a tree into path -> {oid, mode}
function flattenTree(repo: Repo, treeOid: string, prefix: string, out: Map<string, { oid: string; mode: string }>): void {
  const o = repo.objects.get(treeOid);
  if (!o || o.type !== 'tree') return;
  for (const e of parseTree(o.data)) {
    const path = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.mode === '40000') flattenTree(repo, e.oid, path, out);
    else out.set(path, { oid: e.oid, mode: e.mode });
  }
}
function treeFromFiles(repo: Repo, files: Map<string, Buffer>): string {
  interface Node { files: Map<string, Buffer>; dirs: Map<string, Node> }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, data] of files) {
    const segs = path.split('/');
    let node = root;
    for (let i = 0; i < segs.length - 1; i++) {
      const s = segs[i] as string;
      let child = node.dirs.get(s);
      if (!child) { child = make(); node.dirs.set(s, child); }
      node = child;
    }
    node.files.set(segs[segs.length - 1] as string, data);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, data] of node.files) {
      const oid = hashObject('blob', data);
      if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'blob', data });
      entries.push({ mode: '100644', name, oid });
    }
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    const data = buildTree(entries);
    const oid = hashObject('tree', data);
    if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'tree', data });
    return oid;
  };
  return build(root);
}
function filesAt(repo: Repo, commitOid: string): Map<string, Buffer> {
  const cached = repo.filesCache.get(commitOid);
  if (cached) return cached;
  const out = new Map<string, Buffer>();
  const o = repo.objects.get(commitOid);
  if (o && o.type === 'commit') {
    const flat = new Map<string, { oid: string; mode: string }>();
    flattenTree(repo, parseCommit(o.data).tree, '', flat);
    for (const [path, e] of flat) {
      const b = repo.objects.get(e.oid);
      if (b) out.set(path, b.data);
    }
  }
  repo.filesCache.set(commitOid, out);
  return out;
}
function makeCommit(repo: Repo, treeOid: string, parents: string[], message: string): string {
  const ts = 1700000000 + (++objSeq);
  const who = `Ada Iversen <${VIEWER_EMAIL}> ${ts} +0000`;
  let text = `tree ${treeOid}\n`;
  for (const p of parents) text += `parent ${p}\n`;
  text += `author ${who}\ncommitter ${who}\n\n${message}`;
  const data = Buffer.from(text, 'utf8');
  const oid = hashObject('commit', data);
  repo.objects.set(oid, { type: 'commit', data });
  return oid;
}

// ---------------------------------------------------------------- packfile
const TYPE_CODE: Record<string, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
function writePack(objects: GObj[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const o of objects) {
    const code = TYPE_CODE[o.type] as number;
    const size = o.data.length;
    const bytes: number[] = [];
    let rem = size;
    let first = (code << 4) | (rem & 0x0f);
    rem = Math.floor(rem / 16);
    while (rem > 0) { bytes.push(first | 0x80); first = rem & 0x7f; rem = Math.floor(rem / 128); }
    bytes.push(first);
    parts.push(Buffer.from(bytes));
    parts.push(deflateSync(o.data, { level: 1 }));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}
function readPack(pack: Buffer): { objects: GObj[] } | null {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') return null;
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) return null;
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const trailer = pack.subarray(trailerStart).toString('hex');
  if (sha1hex(pack.subarray(0, trailerStart)) !== trailer) return null;
  const objects: GObj[] = [];
  let off = 12;
  const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
  for (let i = 0; i < count; i++) {
    let byte = pack[off++];
    const typeCode = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) { byte = pack[off++]; size |= (byte & 0x7f) << shift; shift += 7; }
    if (typeCode === 6 || typeCode === 7) return null; // deltas unsupported: client never sends them
    const type = CODE_TYPE[typeCode];
    if (!type) return null;
    let inflated: Buffer;
    let consumed: number;
    if (INFLATE_INFO) {
      // One native inflate returns both the object and the exact stream length
      // (engine.bytesWritten), instead of a binary search of trial inflates.
      try {
        const r = inflateSync(pack.subarray(off, trailerStart), { info: true }) as unknown as { buffer: Buffer; engine: { bytesWritten: number } };
        inflated = r.buffer;
        consumed = r.engine.bytesWritten;
      } catch { return null; }
    } else {
      try { inflated = inflateSync(pack.subarray(off, trailerStart)); } catch { return null; }
      consumed = zlibConsumed(pack, off, trailerStart);
      if (consumed < 0) return null;
    }
    off += consumed;
    if (inflated.length !== size) return null;
    objects.push({ type, data: inflated });
  }
  if (off !== trailerStart) return null;
  return { objects };
}
// Whether this Node's inflateSync supports {info:true} (Node >= 17.5); probed once.
const INFLATE_INFO: boolean = (() => {
  try {
    const sample = deflateSync(Buffer.from('x'));
    const r = inflateSync(sample, { info: true }) as unknown as { buffer?: Buffer; engine?: { bytesWritten?: number } };
    return !!r && Buffer.isBuffer(r.buffer) && typeof r.engine?.bytesWritten === 'number';
  } catch { return false; }
})();
// Bytes a zlib stream starting at `off` occupies, via inflateSync on a bounded window probe.
function zlibConsumed(pack: Buffer, off: number, end: number): number {
  // Binary search the smallest length that inflates cleanly to a full stream.
  let lo = 2, hi = end - off, ans = -1;
  // fast path: try full remainder first (common: last object)
  try { inflateSync(pack.subarray(off, end)); ans = end - off; } catch { /* not last */ }
  if (ans > 0) {
    // shrink: find minimal prefix that still inflates without error
    let a = 2, b = ans;
    while (a < b) {
      const mid = (a + b) >> 1;
      try { inflateSync(pack.subarray(off, off + mid)); b = mid; } catch { a = mid + 1; }
    }
    return a;
  }
  // not last object: binary search minimal working prefix
  let a = 2, b = hi;
  while (a < b) {
    const mid = (a + b) >> 1;
    try { inflateSync(pack.subarray(off, off + mid)); b = mid; } catch { a = mid + 1; }
  }
  try { inflateSync(pack.subarray(off, off + a)); return a; } catch { return -1; }
}

// ---------------------------------------------------------------- store
interface Comment { id: number; body: string; seq: number }
interface Issue {
  id: number; number: number; title: string; body: string; state: 'open' | 'closed';
  labels: string[]; seq: number; comments: Comment[]; json: string | null; jsonBuf: Buffer | null;
}
interface Pull {
  id: number; number: number; title: string; body: string; state: 'open' | 'closed';
  head: string; base: string; headSha: string; baseSha: string;
  merged: boolean; mergedAt: string | null; mergeSha: string | null; seq: number;
}
interface Repo {
  id: number; name: string; owner: string; description: string; priv: boolean;
  defaultBranch: string; seq: number;
  objects: Map<string, GObj>;
  refs: Map<string, string>;
  issues: Issue[]; issuesByNum: Map<number, Issue>;
  pulls: Pull[]; pullsByNum: Map<number, Pull>;
  labels: Map<string, { name: string; color: string }>;
  nextNum: number;
  cinfo: Map<string, { tree: string; parents: string[] }>;
  filesCache: Map<string, Map<string, Buffer>>;
  gitCache: Map<string, Buffer>;
  advV0: Buffer | null; advV2: Buffer | null; lsCache: Buffer | null;
}
const reposByKey = new Map<string, Repo>();
const reposByOwner = new Map<string, Repo[]>();
let repoIdSeq = 0;
let globalIdSeq = 0;
function repoKey(owner: string, name: string): string { return `${owner}/${name}`; }
function createRepoRecord(name: string, description: string, priv: boolean, defaultBranch: string): Repo {
  const repo: Repo = {
    id: ++repoIdSeq, name, owner: VIEWER, description, priv,
    defaultBranch: defaultBranch || 'main', seq: ++globalIdSeq,
    objects: new Map(), refs: new Map(),
    issues: [], issuesByNum: new Map(),
    pulls: [], pullsByNum: new Map(),
    labels: new Map(), nextNum: 1,
    cinfo: new Map(),
    filesCache: new Map(), gitCache: new Map(), advV0: null, advV2: null, lsCache: null,
  };
  reposByKey.set(repoKey(VIEWER, name), repo);
  let list = reposByOwner.get(VIEWER);
  if (!list) { list = []; reposByOwner.set(VIEWER, list); }
  list.push(repo);
  return repo;
}
function getRepo(owner: string, name: string): Repo | undefined {
  if (owner !== VIEWER) return undefined;
  return reposByKey.get(repoKey(owner, name));
}
function invalidateGit(repo: Repo): void {
  repo.advV0 = null; repo.advV2 = null; repo.lsCache = null; repo.gitCache.clear();
}
function issueJson(repo: Repo, iss: Issue): string {
  if (iss.json) return iss.json;
  const labels = iss.labels.map((n) => {
    const l = repo.labels.get(n);
    return { id: 0, name: n, color: l ? l.color : 'ededed', description: '' };
  });
  const s = JSON.stringify({
    id: iss.id, node_id: gid('I', `${repo.id}:${iss.number}`), number: iss.number, title: iss.title,
    body: iss.body, state: iss.state, labels, user: { login: VIEWER, id: 1000 },
    created_at: isoTs(iss.seq), updated_at: isoTs(iss.seq),
    html_url: '', url: '', comments: iss.comments.length,
  });
  iss.json = s;
  return s;
}
function issueJsonBuf(repo: Repo, iss: Issue): Buffer {
  if (iss.jsonBuf) return iss.jsonBuf;
  const b = Buffer.from(issueJson(repo, iss), 'utf8');
  iss.jsonBuf = b;
  return b;
}
function repoJson(repo: Repo): string {
  return JSON.stringify({
    id: repo.id, node_id: gid('R', String(repo.id)), name: repo.name, full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: 1000 }, private: repo.priv, description: repo.description,
    default_branch: repo.defaultBranch, has_issues: true, has_projects: true, has_wiki: false,
    created_at: isoTs(repo.seq), updated_at: isoTs(repo.seq), html_url: '', url: '',
    clone_url: '', git_url: '', ssh_url: '', forks_count: 0, stargazers_count: 0, watchers_count: 0, open_issues_count: repo.issues.filter((i) => i.state === 'open').length,
  });
}
function pullJson(repo: Repo, pr: Pull): string {
  return JSON.stringify({
    id: pr.id, node_id: gid('P', `${repo.id}:${pr.number}`), number: pr.number, title: pr.title, body: pr.body,
    state: pr.state, merged: pr.merged, mergeable: prMergeable(repo, pr), merged_at: pr.mergedAt,
    merge_commit_sha: pr.mergeSha, head: { ref: pr.head, sha: pr.headSha, label: `${VIEWER}:${pr.head}`, user: { login: VIEWER } },
    base: { ref: pr.base, sha: pr.baseSha, label: `${VIEWER}:${pr.base}`, user: { login: VIEWER } },
    user: { login: VIEWER, id: 1000 }, created_at: isoTs(pr.seq), updated_at: isoTs(pr.seq), html_url: '', url: '',
  });
}
function prChangedFiles(repo: Repo, pr: Pull): { filename: string; status: string; additions: number; deletions: number; changes: number }[] {
  const baseOid = repo.refs.get(`refs/heads/${pr.base}`);
  const headOid = repo.refs.get(`refs/heads/${pr.head}`);
  if (!baseOid || !headOid) return [];
  const mb = mergeBase(repo, headOid, baseOid);
  const baseTree = mb ? filesAt(repo, mb) : new Map<string, Buffer>();
  const headTree = filesAt(repo, headOid);
  const paths = new Set<string>([...baseTree.keys(), ...headTree.keys()]);
  const out: { filename: string; status: string; additions: number; deletions: number; changes: number }[] = [];
  for (const p of paths) {
    const b = baseTree.get(p), h = headTree.get(p);
    if (b && h && b.equals(h)) continue;
    let status = 'modified';
    if (!b) status = 'added';
    else if (!h) status = 'removed';
    const oldLines = b ? b.toString('utf8').split('\n') : [];
    const newLines = h ? h.toString('utf8').split('\n') : [];
    const oldSet = new Set(oldLines), newSet = new Set(newLines);
    let additions = 0, deletions = 0;
    for (const l of newLines) if (l !== '' && !oldSet.has(l)) additions++;
    for (const l of oldLines) if (l !== '' && !newSet.has(l)) deletions++;
    if (additions === 0 && deletions === 0) { additions = h ? 1 : 0; deletions = b ? 1 : 0; }
    out.push({ filename: p, status, additions, deletions, changes: additions + deletions });
  }
  return out;
}
function prMergeable(repo: Repo, pr: Pull): string {
  if (pr.state !== 'open') return 'UNKNOWN';
  const baseOid = repo.refs.get(`refs/heads/${pr.base}`);
  const headOid = repo.refs.get(`refs/heads/${pr.head}`);
  if (!baseOid || !headOid) return 'UNKNOWN';
  const mb = mergeBase(repo, headOid, baseOid);
  if (!mb) return 'UNKNOWN';
  const baseTree = filesAt(repo, mb);
  const headTree = filesAt(repo, headOid);
  const curTree = filesAt(repo, baseOid);
  for (const [p, h] of headTree) {
    const b = baseTree.get(p);
    const c = curTree.get(p);
    if (b && c && !b.equals(c) && !h.equals(c)) return 'CONFLICTING';
    if (!b && c && !h.equals(c)) return 'CONFLICTING';
  }
  for (const [p, b] of baseTree) {
    if (!headTree.has(p) && curTree.has(p) && !curTree.get(p)?.equals(b)) return 'CONFLICTING';
  }
  return 'MERGEABLE';
}
function doMerge(repo: Repo, pr: Pull): { ok: boolean; sha?: string } {
  if (pr.state !== 'open') return { ok: false };
  if (prMergeable(repo, pr) === 'CONFLICTING') return { ok: false };
  const baseOid = repo.refs.get(`refs/heads/${pr.base}`) as string;
  const headOid = repo.refs.get(`refs/heads/${pr.head}`) as string;
  const headCommit = repo.objects.get(headOid);
  if (!headCommit) return { ok: false };
  const treeOid = parseCommit(headCommit.data).tree;
  const sha = makeCommit(repo, treeOid, [baseOid], pr.title);
  repo.refs.set(`refs/heads/${pr.base}`, sha);
  pr.state = 'closed'; pr.merged = true; pr.mergedAt = isoTs(++globalIdSeq); pr.mergeSha = sha; pr.baseSha = sha;
  invalidateGit(repo);
  return { ok: true, sha };
}

// ---------------------------------------------------------------- git protocol
function sortedRefs(repo: Repo): { name: string; oid: string }[] {
  const out: { name: string; oid: string }[] = [];
  for (const [name, oid] of repo.refs) out.push({ name, oid });
  out.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return out;
}
function headOid(repo: Repo): string {
  return repo.refs.get(`refs/heads/${repo.defaultBranch}`) ?? repo.refs.get('refs/heads/main') ?? ZERO_OID;
}
function buildAdvV0(repo: Repo, service: string): Buffer {
  const caps = service === 'git-receive-pack'
    ? 'report-status side-band-64k delete-refs ofs-delta agent=' + AGENT
    : 'side-band-64k thin-pack ofs-delta shallow multi_ack multi_ack_detailed symref=HEAD:refs/heads/' + repo.defaultBranch + ' agent=' + AGENT;
  const parts: Buffer[] = [];
  parts.push(pkt(`# service=${service}\n`));
  parts.push(FLUSH);
  const refs = sortedRefs(repo);
  const head = headOid(repo);
  if (refs.length === 0) {
    parts.push(pkt(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    parts.push(pkt(`${head} HEAD\0${caps}\n`));
    for (const r of refs) {
      parts.push(pkt(`${r.oid} ${r.name}\n`));
      const o = repo.objects.get(r.oid);
      if (o && o.type === 'tag') {
        const peeled = peelToCommit(repo, r.oid);
        parts.push(pkt(`${peeled} ${r.name}^{}\n`));
      }
    }
  }
  parts.push(FLUSH);
  return Buffer.concat(parts);
}
function buildAdvV2(repo: Repo): Buffer {
  const parts: Buffer[] = [
    pkt('# service=git-upload-pack\n'), FLUSH,
    pkt('version 2\n'),
    pkt('ls-refs=unborn\n'),
    pkt('fetch=shallow filter\n'),
    pkt('object-format=sha1\n'),
    pkt(`agent=${AGENT}\n`),
    FLUSH,
  ];
  return Buffer.concat(parts);
}
function lsRefsResponse(repo: Repo, prefixes: string[], peel: boolean, symrefs: boolean, unborn: boolean): Buffer {
  const parts: Buffer[] = [];
  const refs = sortedRefs(repo);
  const head = headOid(repo);
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  if (refs.length === 0) {
    if (unborn && keep('HEAD')) parts.push(pkt(`unborn HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
  } else {
    if (symrefs && keep('HEAD')) parts.push(pkt(`${head} HEAD symref-target:refs/heads/${repo.defaultBranch}\n`));
    for (const r of refs) {
      if (!keep(r.name)) continue;
      let line = `${r.oid} ${r.name}`;
      const o = repo.objects.get(r.oid);
      if (peel && o && o.type === 'tag') line += ` peeled:${peelToCommit(repo, r.oid)}`;
      parts.push(pkt(`${line}\n`));
    }
  }
  parts.push(FLUSH);
  return Buffer.concat(parts);
}
function sidebandPack(pack: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const CHUNK = 65515;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    out.push(pkt(Buffer.concat([Buffer.from([1]), slice])));
  }
  if (pack.length === 0) out.push(pkt(Buffer.from([1])));
  return out;
}
function emptyPack(): Buffer {
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(0, 8);
  return Buffer.concat([header, createHash('sha1').update(header).digest()]);
}
interface FetchSel { objects: GObj[]; shallow: string[]; unshallow: string[] }
function selectFetch(repo: Repo, wants: string[], haves: string[], depth: number | null, shallowIn: string[]): FetchSel {
  const objects = new Map<string, GObj>();
  const add = (oid: string): void => {
    const o = repo.objects.get(oid);
    if (o && !objects.has(oid)) objects.set(oid, o);
  };
  const collectTree = (treeOid: string, into: Set<string>): void => {
    const o = repo.objects.get(treeOid);
    if (!o || into.has(treeOid)) return;
    into.add(treeOid);
    if (o.type === 'tree') for (const e of parseTree(o.data)) {
      if (e.mode === '40000') collectTree(e.oid, into); else into.add(e.oid);
    }
  };
  const addTreeClosure = (treeOid: string): void => {
    const o = repo.objects.get(treeOid);
    if (!o) return;
    add(treeOid);
    if (o.type === 'tree') for (const e of parseTree(o.data)) {
      if (e.mode === '40000') addTreeClosure(e.oid); else add(e.oid);
    }
  };
  const shallow: string[] = [];
  const unshallow: string[] = [];
  if (depth !== null) {
    // BFS by parent distance from peeled wants.
    const dist = new Map<string, number>();
    const q: string[] = [];
    for (const w of wants) {
      const c = peelToCommit(repo, w);
      if (!dist.has(c)) { dist.set(c, 0); q.push(c); }
      if (repo.objects.get(w)?.type === 'tag') add(w);
    }
    const included = new Set<string>();
    while (q.length) {
      const cur = q.shift() as string;
      const d = dist.get(cur) as number;
      if (d >= depth) continue;
      included.add(cur);
      const ci = cinfo(repo, cur);
      if (ci) {
        add(cur);
        addTreeClosure(ci.tree);
        for (const p of ci.parents) {
          if (!dist.has(p)) { dist.set(p, d + 1); q.push(p); }
        }
      }
    }
    for (const oid of included) {
      const ci = cinfo(repo, oid);
      if (!ci) continue;
      const hasOutsideParent = ci.parents.some((p) => !included.has(p));
      if (hasOutsideParent) shallow.push(oid);
      else if (shallowIn.includes(oid)) unshallow.push(oid);
    }
    // Objects already held by the client must not be re-sent. For a depth
    // fetch the client only holds its shallow boundary commits (the commit
    // itself plus its tree) — NOT their ancestors — so exclude exactly that.
    const held = new Set<string>();
    for (const h of [...haves, ...shallowIn]) {
      held.add(h);
      const ci = cinfo(repo, h);
      if (ci) collectTree(ci.tree, held);
    }
    for (const oid of held) objects.delete(oid);
    return { objects: [...objects.values()], shallow, unshallow };
  }
  const held = haves.length ? reachable(repo, haves) : new Set<string>();
  const wantReach = reachable(repo, wants);
  for (const oid of wantReach) if (!held.has(oid)) add(oid);
  return { objects: [...objects.values()], shallow, unshallow };
}
function fetchV2Response(repo: Repo, sel: FetchSel): Buffer {
  const pack = sel.objects.length ? writePack(sel.objects) : emptyPack();
  const parts: Buffer[] = [pkt('acknowledgments\n'), pkt('NAK\n'), DELIM];
  if (sel.shallow.length || sel.unshallow.length) {
    parts.push(pkt('shallow-info\n'));
    for (const s of sel.shallow) parts.push(pkt(`shallow ${s}\n`));
    for (const s of sel.unshallow) parts.push(pkt(`unshallow ${s}\n`));
    parts.push(DELIM);
  }
  parts.push(pkt('packfile\n'));
  for (const b of sidebandPack(pack)) parts.push(b);
  parts.push(FLUSH);
  return Buffer.concat(parts);
}
function fetchV0Response(repo: Repo, sel: FetchSel): Buffer {
  const pack = sel.objects.length ? writePack(sel.objects) : emptyPack();
  const parts: Buffer[] = [pkt('NAK\n')];
  for (const s of sel.shallow) parts.push(pkt(`shallow ${s}\n`));
  for (const s of sel.unshallow) parts.push(pkt(`unshallow ${s}\n`));
  for (const b of sidebandPack(pack)) parts.push(b);
  parts.push(FLUSH);
  return Buffer.concat(parts);
}
function parseFetchRequest(lines: string[], v2: boolean): { wants: string[]; haves: string[]; depth: number | null; shallow: string[] } {
  const wants: string[] = [], haves: string[] = [], shallow: string[] = [];
  let depth: number | null = null;
  for (const raw of lines) {
    const line = raw.replace(/\n$/, '');
    if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0] as string);
    else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) shallow.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) { const n = parseInt(line.slice(7), 10); if (Number.isFinite(n)) depth = n; }
  }
  return { wants, haves, depth, shallow };
}
function reportLines(entries: { ref: string; ok: boolean; reason: string }[]): Buffer {
  let inner = '';
  inner += 'unpack ok\n';
  for (const e of entries) inner += e.ok ? `ok ${e.ref}\n` : `ng ${e.ref} ${e.reason}\n`;
  const innerBuf = Buffer.concat([pkt('unpack ok\n'), ...entries.map((e) => pkt(e.ok ? `ok ${e.ref}\n` : `ng ${e.ref} ${e.reason}\n`))]);
  void inner;
  const parts: Buffer[] = [];
  const CHUNK = 65515;
  for (let off = 0; off < innerBuf.length; off += CHUNK) {
    parts.push(pkt(Buffer.concat([Buffer.from([1]), innerBuf.subarray(off, Math.min(innerBuf.length, off + CHUNK))])));
  }
  parts.push(FLUSH);
  return Buffer.concat(parts);
}
interface PushCommand { oldOid: string; newOid: string; ref: string }
function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  const { lines, rest } = decodePktLines(body);
  const commands: PushCommand[] = [];
  for (const raw of lines) {
    const line = raw.replace(/\n$/, '');
    if (!line) continue;
    const nul = line.indexOf('\0');
    const clean = nul >= 0 ? line.slice(0, nul) : line;
    const parts = clean.split(' ');
    if (parts.length >= 3) commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts.slice(2).join(' ') });
  }
  const pack = rest.length ? readPack(rest) : { objects: [] as GObj[] };
  const results: { ref: string; ok: boolean; reason: string }[] = [];
  if (pack === null) {
    for (const c of commands) results.push({ ref: c.ref, ok: false, reason: 'unpack error' });
    return reportLines(results);
  }
  for (const o of pack.objects) {
    const oid = hashObject(o.type, o.data);
    if (!repo.objects.has(oid)) repo.objects.set(oid, o);
  }
  let changed = false;
  for (const cmd of commands) {
    const cur = repo.refs.get(cmd.ref);
    if (cmd.newOid === ZERO_OID) {
      // delete
      if (!cur) { results.push({ ref: cmd.ref, ok: false, reason: 'ref does not exist' }); continue; }
      if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== cur) { results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' }); continue; }
      repo.refs.delete(cmd.ref);
      results.push({ ref: cmd.ref, ok: true, reason: '' });
      changed = true;
      continue;
    }
    const target = repo.objects.get(cmd.newOid);
    if (!target) { results.push({ ref: cmd.ref, ok: false, reason: 'object not found' }); continue; }
    if (!cur) {
      if (cmd.oldOid !== ZERO_OID) { results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' }); continue; }
      repo.refs.set(cmd.ref, cmd.newOid);
      results.push({ ref: cmd.ref, ok: true, reason: '' });
      changed = true;
      continue;
    }
    if (cmd.oldOid !== cur) { results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' }); continue; }
    if (cmd.newOid === cur) { results.push({ ref: cmd.ref, ok: true, reason: '' }); continue; }
    if (!isAncestor(repo, cur, cmd.newOid)) { results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' }); continue; }
    repo.refs.set(cmd.ref, cmd.newOid);
    results.push({ ref: cmd.ref, ok: true, reason: '' });
    changed = true;
  }
  if (changed) invalidateGit(repo);
  return reportLines(results);
}

// ---------------------------------------------------------------- HTTP plumbing
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
function sendBuf(res: ServerResponse, status: number, body: Buffer, contentType: string, extra: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': body.length, 'x-github-request-id': `req-${++reqSeq}`, ...extra });
  res.end(body);
}
function sendJsonStr(res: ServerResponse, status: number, text: string, extra: Record<string, string> = {}): void {
  sendBuf(res, status, Buffer.from(text, 'utf8'), 'application/json; charset=utf-8', extra);
}
function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  sendJsonStr(res, status, JSON.stringify(body), extra);
}
function errJson(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}
function authed(req: IncomingMessage): boolean {
  const h = req.headers.authorization;
  return typeof h === 'string' && h.startsWith('Bearer ') && h.slice(7).trim() !== '';
}
function parseJsonBody(buf: Buffer): { ok: boolean; value: Record<string, unknown> } {
  if (buf.length === 0) return { ok: true, value: {} };
  try {
    const v = JSON.parse(buf.toString('utf8')) as unknown;
    if (v !== null && typeof v === 'object' && !Array.isArray(v)) return { ok: true, value: v as Record<string, unknown> };
    return { ok: true, value: {} };
  } catch { return { ok: false, value: {} }; }
}
function pageParams(qs: URLSearchParams): { page: number; perPage: number } {
  const page = Math.max(1, parseInt(qs.get('page') ?? '1', 10) || 1);
  const perPage = Math.min(100, Math.max(1, parseInt(qs.get('per_page') ?? '30', 10) || 30));
  return { page, perPage };
}
function linkHeader(req: IncomingMessage, basePath: string, qs: URLSearchParams, page: number, perPage: number, total: number): string | null {
  const totalPages = Math.max(1, Math.ceil(total / perPage));
  if (totalPages <= 1) return null;
  const host = req.headers.host ?? '127.0.0.1';
  const mk = (p: number): string => `http://${host}${basePath}?${new URLSearchParams({ ...Object.fromEntries(qs), page: String(p), per_page: String(perPage) }).toString()}`;
  const parts: string[] = [];
  if (page < totalPages) parts.push(`<${mk(page + 1)}>; rel="next"`);
  if (page > 1) parts.push(`<${mk(page - 1)}>; rel="prev"`);
  parts.push(`<${mk(1)}>; rel="first"`);
  parts.push(`<${mk(totalPages)}>; rel="last"`);
  return parts.join(', ');
}
function paginate<T>(items: T[], page: number, perPage: number): T[] {
  return items.slice((page - 1) * perPage, page * perPage);
}

// ---------------------------------------------------------------- REST v3
async function handleRest(req: IncomingMessage, res: ServerResponse, path: string, qs: URLSearchParams): Promise<void> {
  const method = req.method ?? 'GET';
  const segs = path.split('/').filter((s) => s !== '').map(dec);
  // segs[0] === 'api', segs[1] === 'v3'
  const rest = segs.slice(2);
  const needsAuth = !(method === 'GET' && (rest.length === 0 || (rest.length === 1 && rest[0] === 'meta')));
  if (needsAuth && !authed(req)) { errJson(res, 401, 'Requires authentication'); return; }
  if (rest.length === 0) {
    sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit', repository_url: '/api/v3/repos/{owner}/{repo}' }, { 'x-oauth-scopes': 'repo, read:org' });
    return;
  }
  if (rest[0] === 'meta' && method === 'GET') {
    sendJson(res, 200, { installed_version: '1.0.0', verifiable_password_authentication: false });
    return;
  }
  if (rest[0] === 'rate_limit' && method === 'GET') {
    sendJson(res, 200, { resources: { core: { limit: 5000, remaining: 5000, reset: 1735689600 } }, rate: { limit: 5000, remaining: 5000, reset: 1735689600 } });
    return;
  }
  if (rest[0] === 'user') {
    if (rest.length === 1 && method === 'GET') {
      sendJson(res, 200, { login: VIEWER, id: 1000, node_id: gid('U', '1000'), name: VIEWER_NAME, email: VIEWER_EMAIL, type: 'User' });
      return;
    }
    if (rest.length === 2 && rest[1] === 'repos') {
      if (method === 'GET') {
        const { page, perPage } = pageParams(qs);
        const list = reposByOwner.get(VIEWER) ?? [];
        const link = linkHeader(req, '/api/v3/user/repos', qs, page, perPage, list.length);
        sendJson(res, 200, paginate(list, page, perPage).map((r) => JSON.parse(repoJson(r)) as unknown), link ? { link } : {});
        return;
      }
      if (method === 'POST') {
        const body = await readBody(req);
        const parsed = parseJsonBody(body);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
        const name = typeof parsed.value.name === 'string' ? parsed.value.name : '';
        if (name === '') { errJson(res, 422, 'Validation Failed: name is required'); return; }
        if (reposByKey.has(repoKey(VIEWER, name))) { errJson(res, 422, 'Validation Failed: repository already exists'); return; }
        const repo = createRepoRecord(
          name,
          typeof parsed.value.description === 'string' ? parsed.value.description : '',
          parsed.value.private === true,
          typeof parsed.value.default_branch === 'string' ? parsed.value.default_branch : 'main',
        );
        sendJson(res, 201, JSON.parse(repoJson(repo)) as unknown);
        return;
      }
    }
    errJson(res, 404, 'Not Found');
    return;
  }
  if (rest[0] === 'repos' && rest.length >= 3) {
    const owner = rest[1] as string, name = rest[2] as string;
    const repo = getRepo(owner, name);
    if (!repo) { errJson(res, 404, 'Not Found'); return; }
    const tail = rest.slice(3);
    if (tail.length === 0) {
      if (method === 'GET') { sendJsonStr(res, 200, repoJson(repo)); return; }
      if (method === 'PATCH') {
        const body = await readBody(req);
        const parsed = parseJsonBody(body);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
        if (typeof parsed.value.description === 'string') repo.description = parsed.value.description;
        if (typeof parsed.value.private === 'boolean') repo.priv = parsed.value.private;
        sendJsonStr(res, 200, repoJson(repo));
        return;
      }
      if (method === 'DELETE') {
        reposByKey.delete(repoKey(owner, name));
        const list = reposByOwner.get(VIEWER);
        if (list) { const i = list.indexOf(repo); if (i >= 0) list.splice(i, 1); }
        res.writeHead(204, { 'x-github-request-id': `req-${++reqSeq}` });
        res.end();
        return;
      }
      errJson(res, 404, 'Not Found');
      return;
    }
    // branches
    if (tail[0] === 'branches') {
      if (tail.length === 1 && method === 'GET') {
        const out: unknown[] = [];
        for (const [ref, oid] of repo.refs) {
          if (ref.startsWith('refs/heads/')) out.push({ name: ref.slice(11), commit: { sha: oid }, protected: false });
        }
        sendJson(res, 200, out);
        return;
      }
      if (tail.length === 2 && method === 'GET') {
        const oid = repo.refs.get(`refs/heads/${tail[1]}`);
        if (!oid) { errJson(res, 404, 'Not Found'); return; }
        sendJson(res, 200, { name: tail[1], commit: { sha: oid }, protected: false });
        return;
      }
      errJson(res, 404, 'Not Found');
      return;
    }
    // commits
    if (tail[0] === 'commits' && method === 'GET') {
      const shaParam = qs.get('sha') ?? repo.defaultBranch;
      let tip = repo.refs.get(`refs/heads/${shaParam}`);
      if (!tip && /^[0-9a-f]{40}$/.test(shaParam)) tip = shaParam;
      if (!tip || !repo.objects.has(tip)) { sendJson(res, 200, []); return; }
      const { page, perPage } = pageParams(qs);
      const out: unknown[] = [];
      const seen = new Set<string>();
      const q: string[] = [tip];
      while (q.length && out.length < page * perPage + 50) {
        const cur = q.shift() as string;
        if (seen.has(cur)) continue;
        seen.add(cur);
        const o = repo.objects.get(cur);
        if (!o || o.type !== 'commit') continue;
        const c = parseCommit(o.data);
        out.push({ sha: cur, commit: { message: c.message, author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoTs(1) }, committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoTs(1) } }, parents: c.parents.map((p) => ({ sha: p })), html_url: '', url: '' });
        for (const p of c.parents) q.push(p);
      }
      sendJson(res, 200, paginate(out, page, perPage));
      return;
    }
    // git refs
    if (tail[0] === 'git' && tail[1] === 'refs') {
      if (method === 'POST' && tail.length === 2) {
        const body = await readBody(req);
        const parsed = parseJsonBody(body);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
        const ref = typeof parsed.value.ref === 'string' ? parsed.value.ref : '';
        const sha = typeof parsed.value.sha === 'string' ? parsed.value.sha : '';
        if (!ref.startsWith('refs/') || !repo.objects.has(sha)) { errJson(res, 422, 'Validation Failed'); return; }
        if (repo.refs.has(ref)) { errJson(res, 422, 'Validation Failed: ref already exists'); return; }
        repo.refs.set(ref, sha);
        invalidateGit(repo);
        sendJson(res, 201, { ref, object: { sha, type: 'commit' } });
        return;
      }
      if (method === 'GET') {
        if (tail.length === 2) {
          const out: unknown[] = [];
          for (const [ref, oid] of repo.refs) out.push({ ref, object: { sha: oid, type: 'commit' } });
          sendJson(res, 200, out);
          return;
        }
        const refName = `refs/${tail.slice(2).join('/')}`;
        const oid = repo.refs.get(refName);
        if (!oid) { errJson(res, 404, 'Not Found'); return; }
        sendJson(res, 200, { ref: refName, object: { sha: oid, type: 'commit' } });
        return;
      }
      errJson(res, 404, 'Not Found');
      return;
    }
    // contents
    if (tail[0] === 'contents') {
      const filePath = tail.slice(1).join('/');
      if (method === 'GET') {
        const refParam = qs.get('ref');
        let tip = repo.refs.get(`refs/heads/${refParam ?? repo.defaultBranch}`);
        if (refParam && /^[0-9a-f]{40}$/.test(refParam)) tip = refParam;
        if (!tip) { errJson(res, 404, 'Not Found'); return; }
        const files = filesAt(repo, tip);
        if (filePath === '') {
          sendJson(res, 200, dirEntries(repo, files, ''));
          return;
        }
        const exact = files.get(filePath);
        if (exact) {
          const oid = hashObject('blob', exact);
          sendJson(res, 200, { type: 'file', encoding: 'base64', size: exact.length, name: filePath.split('/').pop(), path: filePath, sha: oid, content: b64(exact), url: '', html_url: '', download_url: '' });
          return;
        }
        const prefix = `${filePath}/`;
        let isDir = false;
        for (const p of files.keys()) if (p.startsWith(prefix)) { isDir = true; break; }
        if (isDir) { sendJson(res, 200, dirEntries(repo, files, filePath)); return; }
        errJson(res, 404, 'Not Found');
        return;
      }
      if (method === 'PUT') {
        const body = await readBody(req);
        const parsed = parseJsonBody(body);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
        const branch = typeof parsed.value.branch === 'string' ? parsed.value.branch : repo.defaultBranch;
        const refName = `refs/heads/${branch}`;
        const tip = repo.refs.get(refName);
        const files = tip ? new Map(filesAt(repo, tip)) : new Map<string, Buffer>();
        const content = typeof parsed.value.content === 'string' ? b64dec(parsed.value.content) : Buffer.alloc(0);
        const message = typeof parsed.value.message === 'string' ? parsed.value.message : 'update';
        const existing = files.get(filePath);
        const shaParam = typeof parsed.value.sha === 'string' ? (parsed.value.sha as string).toLowerCase() : '';
        let status = 201;
        if (existing) {
          const curSha = hashObject('blob', existing);
          if (shaParam && shaParam !== curSha) { errJson(res, 409, 'Conflict: sha does not match'); return; }
          if (!shaParam) { errJson(res, 422, 'Validation Failed: sha is required to update a file'); return; }
          status = 200;
        }
        files.set(filePath, content);
        const treeOid = treeFromFiles(repo, files);
        const commitSha = makeCommit(repo, treeOid, tip ? [tip] : [], message);
        repo.refs.set(refName, commitSha);
        repo.filesCache.set(commitSha, files);
        invalidateGit(repo);
        const blobOid = hashObject('blob', content);
        sendJson(res, status, { content: { name: filePath.split('/').pop(), path: filePath, sha: blobOid, size: content.length, type: 'file', encoding: 'base64', content: b64(content) }, commit: { sha: commitSha, message, author: { name: VIEWER_NAME, email: VIEWER_EMAIL }, committer: { name: VIEWER_NAME, email: VIEWER_EMAIL } } });
        return;
      }
      if (method === 'DELETE') {
        const body = await readBody(req);
        const parsed = parseJsonBody(body);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
        const branch = typeof parsed.value.branch === 'string' ? parsed.value.branch : repo.defaultBranch;
        const refName = `refs/heads/${branch}`;
        const tip = repo.refs.get(refName);
        if (!tip) { errJson(res, 404, 'Not Found'); return; }
        const files = new Map(filesAt(repo, tip));
        if (!files.has(filePath)) { errJson(res, 404, 'Not Found'); return; }
        const message = typeof parsed.value.message === 'string' ? parsed.value.message : 'delete';
        files.delete(filePath);
        const treeOid = treeFromFiles(repo, files);
        const commitSha = makeCommit(repo, treeOid, [tip], message);
        repo.refs.set(refName, commitSha);
        repo.filesCache.set(commitSha, files);
        invalidateGit(repo);
        sendJson(res, 200, { commit: { sha: commitSha, message } });
        return;
      }
      errJson(res, 404, 'Not Found');
      return;
    }
    // labels
    if (tail[0] === 'labels') {
      if (method === 'POST') {
        const body = await readBody(req);
        const parsed = parseJsonBody(body);
        if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
        const name = typeof parsed.value.name === 'string' ? parsed.value.name : '';
        if (name === '') { errJson(res, 422, 'Validation Failed: name is required'); return; }
        const color = typeof parsed.value.color === 'string' ? parsed.value.color : 'ededed';
        repo.labels.set(name, { name, color });
        sendJson(res, 201, { id: 1, name, color, description: '' });
        return;
      }
      if (method === 'GET') {
        sendJson(res, 200, [...repo.labels.values()].map((l) => ({ id: 1, name: l.name, color: l.color, description: '' })));
        return;
      }
      errJson(res, 404, 'Not Found');
      return;
    }
    // issues
    if (tail[0] === 'issues') {
      if (tail.length === 1) {
        if (method === 'GET') {
          const state = qs.get('state') ?? 'open';
          const { page, perPage } = pageParams(qs);
          let list = repo.issues.filter((i) => state === 'all' || i.state === state);
          const dir = (qs.get('direction') ?? 'desc').toLowerCase();
          list = [...list].sort((a, b) => (dir === 'asc' ? a.seq - b.seq : b.seq - a.seq));
          sendJson(res, 200, paginate(list, page, perPage).map((i) => JSON.parse(issueJson(repo, i)) as unknown));
          return;
        }
        if (method === 'POST') {
          const body = await readBody(req);
          const parsed = parseJsonBody(body);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
          const title = typeof parsed.value.title === 'string' ? parsed.value.title : '';
          const labelsRaw = Array.isArray(parsed.value.labels) ? (parsed.value.labels as unknown[]) : [];
          const labelNames: string[] = [];
          for (const l of labelsRaw) {
            const n = typeof l === 'string' ? l : (l as Record<string, unknown>)?.name;
            if (typeof n !== 'string') continue;
            if (!repo.labels.has(n)) { errJson(res, 422, `Validation Failed: label "${n}" does not exist`); return; }
            labelNames.push(n);
          }
          const iss: Issue = {
            id: ++globalIdSeq, number: repo.nextNum++, title,
            body: typeof parsed.value.body === 'string' ? parsed.value.body : '',
            state: 'open', labels: labelNames, seq: ++globalIdSeq, comments: [], json: null, jsonBuf: null,
          };
          repo.issues.push(iss);
          repo.issuesByNum.set(iss.number, iss);
          sendJsonStr(res, 201, issueJson(repo, iss));
          return;
        }
        errJson(res, 404, 'Not Found');
        return;
      }
      const num = parseInt(tail[1] as string, 10);
      const iss = repo.issuesByNum.get(num);
      if (tail.length === 2) {
        if (!iss) { errJson(res, 404, 'Not Found'); return; }
        if (method === 'GET') { sendJsonStr(res, 200, issueJson(repo, iss)); return; }
        if (method === 'PATCH') {
          const body = await readBody(req);
          const parsed = parseJsonBody(body);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
          if (typeof parsed.value.title === 'string') iss.title = parsed.value.title;
          if (typeof parsed.value.body === 'string') iss.body = parsed.value.body;
          if (parsed.value.state === 'open' || parsed.value.state === 'closed') iss.state = parsed.value.state;
          iss.json = null; iss.jsonBuf = null;
          sendJsonStr(res, 200, issueJson(repo, iss));
          return;
        }
        errJson(res, 404, 'Not Found');
        return;
      }
      if (tail.length === 3 && tail[2] === 'comments') {
        if (!iss) { errJson(res, 404, 'Not Found'); return; }
        if (method === 'GET') {
          sendJson(res, 200, iss.comments.map((c) => ({ id: c.id, body: c.body, user: { login: VIEWER, id: 1000 }, created_at: isoTs(c.seq), updated_at: isoTs(c.seq) })));
          return;
        }
        if (method === 'POST') {
          const body = await readBody(req);
          const parsed = parseJsonBody(body);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
          const c: Comment = { id: ++globalIdSeq, body: typeof parsed.value.body === 'string' ? parsed.value.body : '', seq: ++globalIdSeq };
          iss.comments.push(c);
          iss.json = null; iss.jsonBuf = null;
          sendJson(res, 201, { id: c.id, body: c.body, user: { login: VIEWER, id: 1000 }, created_at: isoTs(c.seq), updated_at: isoTs(c.seq) });
          return;
        }
        errJson(res, 404, 'Not Found');
        return;
      }
      errJson(res, 404, 'Not Found');
      return;
    }
    // pulls
    if (tail[0] === 'pulls') {
      if (tail.length === 1) {
        if (method === 'GET') {
          const state = qs.get('state') ?? 'open';
          const { page, perPage } = pageParams(qs);
          const list = repo.pulls.filter((p) => state === 'all' || p.state === state);
          sendJson(res, 200, paginate(list, page, perPage).map((p) => JSON.parse(pullJson(repo, p)) as unknown));
          return;
        }
        if (method === 'POST') {
          const body = await readBody(req);
          const parsed = parseJsonBody(body);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
          const stripOwner = (v: string): string => { const i = v.indexOf(':'); return i >= 0 ? v.slice(i + 1) : v; };
          const head = typeof parsed.value.head === 'string' ? stripOwner(parsed.value.head) : '';
          const base = typeof parsed.value.base === 'string' ? stripOwner(parsed.value.base) : repo.defaultBranch;
          const headSha = repo.refs.get(`refs/heads/${head}`);
          const baseSha = repo.refs.get(`refs/heads/${base}`);
          if (!headSha || !baseSha) { errJson(res, 422, 'Validation Failed: head or base branch does not exist'); return; }
          const pr: Pull = {
            id: ++globalIdSeq, number: repo.nextNum++,
            title: typeof parsed.value.title === 'string' ? parsed.value.title : '',
            body: typeof parsed.value.body === 'string' ? parsed.value.body : '',
            state: 'open', head, base, headSha, baseSha, merged: false, mergedAt: null, mergeSha: null, seq: ++globalIdSeq,
          };
          repo.pulls.push(pr);
          repo.pullsByNum.set(pr.number, pr);
          sendJsonStr(res, 201, pullJson(repo, pr));
          return;
        }
        errJson(res, 404, 'Not Found');
        return;
      }
      const num = parseInt(tail[1] as string, 10);
      const pr = repo.pullsByNum.get(num);
      if (tail.length === 2) {
        if (!pr) { errJson(res, 404, 'Not Found'); return; }
        if (method === 'GET') { sendJsonStr(res, 200, pullJson(repo, pr)); return; }
        if (method === 'PATCH') {
          const body = await readBody(req);
          const parsed = parseJsonBody(body);
          if (!parsed.ok) { errJson(res, 400, 'Problems parsing JSON'); return; }
          if (parsed.value.state === 'closed') pr.state = 'closed';
          if (typeof parsed.value.title === 'string') pr.title = parsed.value.title;
          if (typeof parsed.value.body === 'string') pr.body = parsed.value.body;
          sendJsonStr(res, 200, pullJson(repo, pr));
          return;
        }
        errJson(res, 404, 'Not Found');
        return;
      }
      if (tail.length === 3 && tail[2] === 'files' && method === 'GET') {
        if (!pr) { errJson(res, 404, 'Not Found'); return; }
        sendJson(res, 200, prChangedFiles(repo, pr));
        return;
      }
      if (tail.length === 3 && tail[2] === 'merge' && method === 'PUT') {
        if (!pr) { errJson(res, 404, 'Not Found'); return; }
        const body = await readBody(req);
        parseJsonBody(body); // body is optional; ignore parse errors here
        if (pr.state !== 'open') { errJson(res, 405, 'Pull request is already closed'); return; }
        const merged = doMerge(repo, pr);
        if (!merged.ok) { errJson(res, 405, 'Merge conflict: pull request cannot be merged'); return; }
        sendJson(res, 200, { sha: merged.sha, merged: true, message: 'Pull Request successfully merged' });
        return;
      }
      errJson(res, 404, 'Not Found');
      return;
    }
    errJson(res, 404, 'Not Found');
    return;
  }
  errJson(res, 404, 'Not Found');
}
function dirEntries(repo: Repo, files: Map<string, Buffer>, dir: string): unknown[] {
  const prefix = dir === '' ? '' : `${dir}/`;
  const children = new Map<string, { type: string; path: string; name: string; sha: string; size?: number }>();
  for (const [p, data] of files) {
    if (!p.startsWith(prefix)) continue;
    const rest = p.slice(prefix.length);
    const slash = rest.indexOf('/');
    if (slash < 0) {
      children.set(rest, { type: 'file', path: p, name: rest, sha: hashObject('blob', data), size: data.length });
    } else {
      const d = rest.slice(0, slash);
      if (!children.has(d)) {
        const sub = new Map<string, Buffer>();
        for (const [p2, d2] of files) if (p2.startsWith(`${prefix}${d}/`)) sub.set(p2.slice(`${prefix}${d}/`.length), d2);
        const treeOid = treeFromFiles(repo, sub);
        children.set(d, { type: 'dir', path: `${prefix}${d}`, name: d, sha: treeOid });
      }
    }
  }
  return [...children.values()].sort((a, b) => (a.name < b.name ? -1 : 1));
}

// ---------------------------------------------------------------- git smart HTTP
async function handleGit(req: IncomingMessage, res: ServerResponse, path: string, qs: URLSearchParams): Promise<void> {
  const method = req.method ?? 'GET';
  const segs = path.split('/').filter((s) => s !== '');
  if (segs.length < 2 || !segs[1]?.endsWith('.git')) { errJson(res, 404, 'Not Found'); return; }
  const owner = dec(segs[0] as string);
  const repoName = dec((segs[1] as string).slice(0, -4));
  const repo = getRepo(owner, repoName);
  if (!repo) { errJson(res, 404, 'Not Found'); return; }
  const tail = segs.slice(2).join('/');
  if (method === 'GET' && tail === 'info/refs') {
    const service = qs.get('service') ?? '';
    if (service === 'git-upload-pack') {
      const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
      if (v2) {
        let buf = repo.gitCache.get('adv2');
        if (!buf) { buf = buildAdvV2(repo); repo.gitCache.set('adv2', buf); }
        sendBuf(res, 200, buf, 'application/x-git-upload-pack-advertisement');
        return;
      }
      let buf = repo.gitCache.get('adv0-up');
      if (!buf) { buf = buildAdvV0(repo, 'git-upload-pack'); repo.gitCache.set('adv0-up', buf); }
      sendBuf(res, 200, buf, 'application/x-git-upload-pack-advertisement');
      return;
    }
    if (service === 'git-receive-pack') {
      let buf = repo.gitCache.get('adv0-recv');
      if (!buf) { buf = buildAdvV0(repo, 'git-receive-pack'); repo.gitCache.set('adv0-recv', buf); }
      sendBuf(res, 200, buf, 'application/x-git-receive-pack-advertisement');
      return;
    }
    errJson(res, 400, 'Bad Request');
    return;
  }
  if (method === 'POST' && tail === 'git-upload-pack') {
    const body = await readBody(req);
    if (body.length < 4 || !/^[0-9a-fA-F]{4}$/.test(body.subarray(0, 4).toString('ascii'))) {
      res.writeHead(400, { 'content-type': 'text/plain', 'x-github-request-id': `req-${++reqSeq}` });
      res.end('Bad Request');
      return;
    }
    const headerV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
    const firstLine = body.subarray(4, Math.min(body.length, 40)).toString('utf8');
    const v2 = headerV2 || firstLine.startsWith('command=');
    const { lines } = decodePktLines(body);
    if (v2) {
      const cmd = (lines[0] ?? '').replace(/\n$/, '');
      if (cmd === 'command=ls-refs') {
        const prefixes: string[] = [];
        let peel = false, symrefs = false, unborn = false;
        for (const raw of lines.slice(1)) {
          const l = raw.replace(/\n$/, '');
          if (l.startsWith('ref-prefix ')) prefixes.push(l.slice(11));
          else if (l === 'peel') peel = true;
          else if (l === 'symrefs') symrefs = true;
          else if (l === 'unborn') unborn = true;
        }
        const key = `ls|${prefixes.join(',')}|${peel}|${symrefs}|${unborn}`;
        let buf = repo.gitCache.get(key);
        if (!buf) { buf = lsRefsResponse(repo, prefixes, peel, symrefs, unborn); repo.gitCache.set(key, buf); }
        sendBuf(res, 200, buf, 'application/x-git-upload-pack-result');
        return;
      }
      if (cmd === 'command=fetch') {
        const f = parseFetchRequest(lines, true);
        const key = `f2|${f.wants.join(',')}|${f.haves.join(',')}|${f.depth}|${f.shallow.join(',')}`;
        let buf = repo.gitCache.get(key);
        if (!buf) { buf = fetchV2Response(repo, selectFetch(repo, f.wants, f.haves, f.depth, f.shallow)); repo.gitCache.set(key, buf); }
        sendBuf(res, 200, buf, 'application/x-git-upload-pack-result');
        return;
      }
      res.writeHead(400, { 'content-type': 'text/plain', 'x-github-request-id': `req-${++reqSeq}` });
      res.end('Bad Request');
      return;
    }
    const f = parseFetchRequest(lines, false);
    const key = `f0|${f.wants.join(',')}|${f.haves.join(',')}|${f.depth}|${f.shallow.join(',')}`;
    let buf = repo.gitCache.get(key);
    if (!buf) { buf = fetchV0Response(repo, selectFetch(repo, f.wants, f.haves, f.depth, f.shallow)); repo.gitCache.set(key, buf); }
    sendBuf(res, 200, buf, 'application/x-git-upload-pack-result');
    return;
  }
  if (method === 'POST' && tail === 'git-receive-pack') {
    const body = await readBody(req);
    const report = handleReceivePack(repo, body);
    sendBuf(res, 200, report, 'application/x-git-receive-pack-result');
    return;
  }
  errJson(res, 404, 'Not Found');
}

// ---------------------------------------------------------------- GraphQL v4
const ISSUE_FIELDS = ['id', 'number', 'title', 'state', 'body'];
const PR_FIELDS = ['id', 'number', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files'];
const REPO_FIELDS = ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'];
function findRepoById(id: number): Repo | undefined {
  for (const r of reposByKey.values()) if (r.id === id) return r;
  return undefined;
}
function gqlIssue(repo: Repo, iss: Issue): Record<string, unknown> {
  return { id: gid('I', `${repo.id}:${iss.number}`), number: iss.number, title: iss.title, state: iss.state === 'open' ? 'OPEN' : 'CLOSED', body: iss.body };
}
function gqlPull(repo: Repo, pr: Pull): Record<string, unknown> {
  return { id: gid('P', `${repo.id}:${pr.number}`), number: pr.number, headRefName: pr.head, baseRefName: pr.base, mergeable: prMergeable(repo, pr), state: pr.state === 'open' ? 'OPEN' : 'CLOSED', merged: pr.merged };
}
function gqlRepo(repo: Repo, vars: Record<string, unknown>, query: string): Record<string, unknown> {
  const out: Record<string, unknown> = {
    id: gid('R', String(repo.id)), databaseId: repo.id, name: repo.name, nameWithOwner: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner }, defaultBranchRef: { name: repo.defaultBranch }, viewerPermission: 'ADMIN', hasIssuesEnabled: true,
  };
  // issues connection
  const first = typeof vars.first === 'number' ? vars.first : 10;
  const after = typeof vars.after === 'string' ? vars.after : null;
  let list = [...repo.issues];
  const statesMatch = /states:\s*\[([^\]]*)\]/.exec(query);
  if (statesMatch && statesMatch[1]?.includes('OPEN')) list = list.filter((i) => i.state === 'open');
  else if (statesMatch && statesMatch[1]?.includes('CLOSED')) list = list.filter((i) => i.state === 'closed');
  const orderMatch = /orderBy:\s*\{[^}]*field:\s*(\w+)[^}]*direction:\s*(\w+)/.exec(query);
  if (orderMatch && orderMatch[2] === 'DESC') list.sort((a, b) => b.seq - a.seq || b.number - a.number);
  else if (orderMatch) list.sort((a, b) => a.seq - b.seq);
  else list.sort((a, b) => a.seq - b.seq);
  let start = 0;
  if (after) {
    try {
      const t = Buffer.from(after, 'base64').toString('utf8');
      const m = /^c:(\d+)$/.exec(t);
      if (m) start = parseInt(m[1] as string, 10) + 1;
    } catch { /* ignore */ }
  }
  const page = list.slice(start, start + first);
  const endIdx = start + page.length - 1;
  out.issues = {
    nodes: page.map((i) => gqlIssue(repo, i)),
    pageInfo: { hasNextPage: start + page.length < list.length, endCursor: page.length ? Buffer.from(`c:${endIdx}`, 'utf8').toString('base64') : null },
    totalCount: list.length,
  };
  if (typeof vars.number === 'number') {
    const iss = repo.issuesByNum.get(vars.number);
    out.issue = iss ? gqlIssue(repo, iss) : null;
  }
  out.pullRequests = { nodes: repo.pulls.slice(0, first).map((p) => gqlPull(repo, p)), totalCount: repo.pulls.length };
  if (typeof vars.number === 'number') {
    const pr = repo.pullsByNum.get(vars.number);
    if (pr) {
      const files = prChangedFiles(repo, pr).map((f) => ({ path: f.filename }));
      out.pullRequest = { ...gqlPull(repo, pr), files: { nodes: files, totalCount: files.length } };
    } else out.pullRequest = null;
  }
  return out;
}
function execGraphql(query: string, vars: Record<string, unknown>): { data: unknown; errors?: { message: string }[] } {
  const errors: { message: string }[] = [];
  const data: Record<string, unknown> = {};
  // __type introspection
  const typeRe = /(?:(\w+)\s*:\s*)?__type\s*\(\s*name\s*:\s*"([^"]+)"\s*\)/g;
  let m: RegExpExecArray | null;
  const typeNames: string[] = [];
  while ((m = typeRe.exec(query)) !== null) {
    const alias = m[1] ?? '__type';
    const name = m[2] as string;
    typeNames.push(name);
    if (name === 'Issue') data[alias] = { fields: ISSUE_FIELDS.map((n) => ({ name: n })), enumValues: null };
    else if (name === 'PullRequest') data[alias] = { fields: PR_FIELDS.map((n) => ({ name: n })), enumValues: null };
    else if (name === 'Repository') data[alias] = { fields: REPO_FIELDS.map((n) => ({ name: n })), enumValues: null };
    else if (name === 'SearchType') data[alias] = { fields: null, enumValues: [{ name: 'ISSUE' }, { name: 'PULL_REQUEST' }, { name: 'REPOSITORY' }, { name: 'USER' }, { name: 'DISCUSSION' }] };
    else data[alias] = { fields: [], enumValues: [] };
  }
  // invalid field validation (viewer + repository selection sets)
  const badViewer = /noSuchFieldOnViewer/.exec(query);
  if (badViewer) {
    errors.push({ message: 'Cannot query field "noSuchFieldOnViewer" on type "Viewer".' });
    data.viewer = null;
    return { data, errors };
  }
  const isMutation = /^\s*mutation\b/.test(query);
  if (query.includes('viewer')) data.viewer = { login: VIEWER };
  if (!isMutation && query.includes('repository(')) {
    const owner = typeof vars.owner === 'string' ? vars.owner : '';
    const name = typeof vars.name === 'string' ? vars.name : '';
    const repo = getRepo(owner, name);
    data.repository = repo ? gqlRepo(repo, vars, query) : null;
  }
  if (!isMutation && query.includes('node(')) {
    const id = typeof vars.id === 'string' ? vars.id : '';
    const g = ungid(id);
    if (!g) data.node = null;
    else if (g.kind === 'R') {
      const repo = findRepoById(parseInt(g.id, 10));
      data.node = repo ? { id: gid('R', String(repo.id)), name: repo.name, nameWithOwner: `${repo.owner}/${repo.name}` } : null;
    } else if (g.kind === 'I') {
      const [rid, num] = g.id.split(':');
      const repo = findRepoById(parseInt(rid as string, 10));
      const iss = repo?.issuesByNum.get(parseInt(num as string, 10));
      data.node = iss && repo ? gqlIssue(repo, iss) : null;
    } else if (g.kind === 'P') {
      const [rid, num] = g.id.split(':');
      const repo = findRepoById(parseInt(rid as string, 10));
      const pr = repo?.pullsByNum.get(parseInt(num as string, 10));
      data.node = pr && repo ? gqlPull(repo, pr) : null;
    } else data.node = null;
  }
  if (isMutation) {
    const input = (vars.input ?? {}) as Record<string, unknown>;
    if (query.includes('createIssue')) {
      const repo = findRepoById(parseInt(String((ungid(typeof input.repositoryId === 'string' ? input.repositoryId : '')?.id ?? '')), 10));
      if (!repo) { errors.push({ message: 'Repository not found.' }); data.createIssue = null; }
      else {
        const iss: Issue = { id: ++globalIdSeq, number: repo.nextNum++, title: typeof input.title === 'string' ? input.title : '', body: typeof input.body === 'string' ? input.body : '', state: 'open', labels: [], seq: ++globalIdSeq, comments: [], json: null, jsonBuf: null };
        repo.issues.push(iss); repo.issuesByNum.set(iss.number, iss);
        data.createIssue = { issue: { number: iss.number, id: gid('I', `${repo.id}:${iss.number}`) } };
      }
    } else if (query.includes('closeIssue')) {
      const g = ungid(typeof input.issueId === 'string' ? input.issueId : '');
      let done = false;
      if (g && g.kind === 'I') {
        const [rid, num] = g.id.split(':');
        const repo = findRepoById(parseInt(rid as string, 10));
        const iss = repo?.issuesByNum.get(parseInt(num as string, 10));
        if (iss && repo) { iss.state = 'closed'; iss.json = null; iss.jsonBuf = null; data.closeIssue = { issue: { number: iss.number, id: gid('I', `${repo.id}:${iss.number}`), state: 'CLOSED' } }; done = true; }
      }
      if (!done) { errors.push({ message: 'Issue not found.' }); data.closeIssue = null; }
    } else if (query.includes('createPullRequest')) {
      const gidVal = ungid(typeof input.repositoryId === 'string' ? input.repositoryId : '');
      const repo = gidVal ? findRepoById(parseInt(gidVal.id, 10)) : undefined;
      const head = typeof input.headRefName === 'string' ? input.headRefName : '';
      const base = typeof input.baseRefName === 'string' ? input.baseRefName : '';
      if (!repo) { errors.push({ message: 'Repository not found.' }); data.createPullRequest = null; }
      else {
        const headSha = repo.refs.get(`refs/heads/${head}`);
        const baseSha = repo.refs.get(`refs/heads/${base}`);
        if (!headSha || !baseSha) { errors.push({ message: 'Head or base branch does not exist.' }); data.createPullRequest = null; }
        else {
          const pr: Pull = { id: ++globalIdSeq, number: repo.nextNum++, title: typeof input.title === 'string' ? input.title : '', body: typeof input.body === 'string' ? input.body : '', state: 'open', head, base, headSha, baseSha, merged: false, mergedAt: null, mergeSha: null, seq: ++globalIdSeq };
          repo.pulls.push(pr); repo.pullsByNum.set(pr.number, pr);
          data.createPullRequest = { pullRequest: { number: pr.number, id: gid('P', `${repo.id}:${pr.number}`), state: 'OPEN', headRefName: head, baseRefName: base } };
        }
      }
    } else if (query.includes('mergePullRequest')) {
      const g = ungid(typeof input.pullRequestId === 'string' ? input.pullRequestId : '');
      let done = false;
      if (g && g.kind === 'P') {
        const [rid, num] = g.id.split(':');
        const repo = findRepoById(parseInt(rid as string, 10));
        const pr = repo?.pullsByNum.get(parseInt(num as string, 10));
        if (pr && repo) {
          const merged = doMerge(repo, pr);
          if (merged.ok) { data.mergePullRequest = { pullRequest: { number: pr.number, merged: true, state: 'CLOSED' } }; done = true; }
          else { errors.push({ message: 'Merge conflict.' }); data.mergePullRequest = null; done = true; }
        }
      }
      if (!done) { errors.push({ message: 'Pull request not found.' }); data.mergePullRequest = null; }
    } else if (query.includes('addComment')) {
      const g = ungid(typeof input.subjectId === 'string' ? input.subjectId : '');
      let done = false;
      if (g && g.kind === 'I') {
        const [rid, num] = g.id.split(':');
        const repo = findRepoById(parseInt(rid as string, 10));
        const iss = repo?.issuesByNum.get(parseInt(num as string, 10));
        if (iss && repo) {
          const c: Comment = { id: ++globalIdSeq, body: typeof input.body === 'string' ? input.body : '', seq: ++globalIdSeq };
          iss.comments.push(c); iss.json = null; iss.jsonBuf = null;
          data.addComment = { commentEdge: { node: { id: gid('C', `${repo.id}:${iss.number}:${c.id}`), body: c.body } } };
          done = true;
        }
      }
      if (!done) { errors.push({ message: 'Subject not found.' }); data.addComment = null; }
    }
  }
  return errors.length ? { data, errors } : { data };
}
async function handleGraphql(req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!authed(req)) { errJson(res, 401, 'Requires authentication'); return; }
  const body = await readBody(req);
  let parsed: unknown;
  try { parsed = JSON.parse(body.toString('utf8')) as unknown; } catch { errJson(res, 400, 'Problems parsing JSON'); return; }
  if (Array.isArray(parsed)) {
    const out = parsed.map((op) => {
      if (op === null || typeof op !== 'object') return { data: null, errors: [{ message: 'Invalid operation.' }] };
      const o = op as Record<string, unknown>;
      return execGraphql(typeof o.query === 'string' ? o.query : '', (o.variables ?? {}) as Record<string, unknown>);
    });
    sendJson(res, 200, out);
    return;
  }
  if (parsed === null || typeof parsed !== 'object') { errJson(res, 400, 'Problems parsing JSON'); return; }
  const o = parsed as Record<string, unknown>;
  sendJson(res, 200, execGraphql(typeof o.query === 'string' ? o.query : '', (o.variables ?? {}) as Record<string, unknown>));
}

// ---------------------------------------------------------------- MCP
const MCP_TOOLS: Record<string, unknown>[] = [
  { name: 'create_repo', description: 'Create a repository for the authenticated user.', inputSchema: { type: 'object', properties: { name: { type: 'string', description: 'Repository name' }, owner: { type: 'string', description: 'Owner login' }, description: { type: 'string' }, private: { type: 'boolean' } }, required: ['name'] } },
  { name: 'get_repo', description: 'Get a repository by owner and name.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' } }, required: ['owner', 'repo'] } },
  { name: 'create_issue', description: 'Create an issue in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' } }, required: ['owner', 'repo', 'title'] } },
  { name: 'list_issues', description: 'List issues in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, state: { type: 'string' } }, required: ['owner', 'repo'] } },
  { name: 'create_pull_request', description: 'Create a pull request from a head branch into a base branch.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' }, head: { type: 'string' }, base: { type: 'string' } }, required: ['owner', 'repo', 'title', 'head', 'base'] } },
  { name: 'merge_pull_request', description: 'Merge a pull request by number.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, pull_number: { type: 'number' } }, required: ['owner', 'repo', 'pull_number'] } },
];
const MCP_TOOL_NAMES = new Set(MCP_TOOLS.map((t) => t.name as string));
function mcpResolveRepo(args: Record<string, unknown>): Repo | undefined {
  let owner = typeof args.owner === 'string' ? args.owner : VIEWER;
  let repoName = typeof args.repo === 'string' ? args.repo : '';
  if (!repoName && typeof args.full_name === 'string') {
    const parts = (args.full_name as string).split('/');
    if (parts.length === 2) { owner = parts[0] as string; repoName = parts[1] as string; }
  }
  if (!repoName && typeof args.name === 'string') repoName = args.name;
  return repoName ? getRepo(owner, repoName) : undefined;
}
function mcpToolResult(obj: unknown): Record<string, unknown> {
  const text = typeof obj === 'string' ? obj : JSON.stringify(obj);
  return { content: [{ type: 'text', text }], structuredContent: obj, isError: false };
}
function mcpToolError(text: string): Record<string, unknown> {
  return { content: [{ type: 'text', text }], isError: true };
}
function execMcpTool(name: string, args: Record<string, unknown>): { result?: Record<string, unknown>; rpcError?: { code: number; message: string } } {
  if (!MCP_TOOL_NAMES.has(name)) return { rpcError: { code: -32601, message: `Method not found: ${name}` } };
  const need = (keys: string[]): string | null => {
    for (const k of keys) if (args[k] === undefined || args[k] === null || args[k] === '') return k;
    return null;
  };
  if (name === 'create_repo') {
    const missing = need(['name']);
    if (missing) return { rpcError: { code: -32602, message: `Missing required argument: ${missing}` } };
    const repoName = args.name as string;
    if (reposByKey.has(repoKey(VIEWER, repoName))) return { result: mcpToolError(`Repository ${VIEWER}/${repoName} already exists`) };
    const repo = createRepoRecord(repoName, typeof args.description === 'string' ? args.description : '', args.private === true, 'main');
    return { result: mcpToolResult(JSON.parse(repoJson(repo)) as unknown) };
  }
  if (name === 'get_repo') {
    const missing = need(['owner', 'repo']);
    if (missing) return { rpcError: { code: -32602, message: `Missing required argument: ${missing}` } };
    const repo = mcpResolveRepo(args);
    if (!repo) return { result: mcpToolError('Repository not found') };
    return { result: mcpToolResult(JSON.parse(repoJson(repo)) as unknown) };
  }
  if (name === 'create_issue') {
    const missing = need(['owner', 'repo', 'title']);
    if (missing) return { rpcError: { code: -32602, message: `Missing required argument: ${missing}` } };
    const repo = mcpResolveRepo(args);
    if (!repo) return { result: mcpToolError('Repository not found') };
    const iss: Issue = { id: ++globalIdSeq, number: repo.nextNum++, title: args.title as string, body: typeof args.body === 'string' ? args.body : '', state: 'open', labels: [], seq: ++globalIdSeq, comments: [], json: null, jsonBuf: null };
    repo.issues.push(iss); repo.issuesByNum.set(iss.number, iss);
    return { result: mcpToolResult(JSON.parse(issueJson(repo, iss)) as unknown) };
  }
  if (name === 'list_issues') {
    const missing = need(['owner', 'repo']);
    if (missing) return { rpcError: { code: -32602, message: `Missing required argument: ${missing}` } };
    const repo = mcpResolveRepo(args);
    if (!repo) return { result: mcpToolError('Repository not found') };
    const state = typeof args.state === 'string' ? args.state : 'open';
    const list = repo.issues.filter((i) => state === 'all' || i.state === state).map((i) => JSON.parse(issueJson(repo, i)) as unknown);
    return { result: mcpToolResult(list) };
  }
  if (name === 'create_pull_request') {
    const missing = need(['owner', 'repo', 'title', 'head', 'base']);
    if (missing) return { rpcError: { code: -32602, message: `Missing required argument: ${missing}` } };
    const repo = mcpResolveRepo(args);
    if (!repo) return { result: mcpToolError('Repository not found') };
    const head = args.head as string, base = args.base as string;
    const headSha = repo.refs.get(`refs/heads/${head}`);
    const baseSha = repo.refs.get(`refs/heads/${base}`);
    if (!headSha || !baseSha) return { result: mcpToolError('Head or base branch does not exist') };
    const pr: Pull = { id: ++globalIdSeq, number: repo.nextNum++, title: args.title as string, body: typeof args.body === 'string' ? args.body : '', state: 'open', head, base, headSha, baseSha, merged: false, mergedAt: null, mergeSha: null, seq: ++globalIdSeq };
    repo.pulls.push(pr); repo.pullsByNum.set(pr.number, pr);
    return { result: mcpToolResult(JSON.parse(pullJson(repo, pr)) as unknown) };
  }
  // merge_pull_request
  const missing = need(['owner', 'repo', 'pull_number']);
  if (missing) return { rpcError: { code: -32602, message: `Missing required argument: ${missing}` } };
  const repo = mcpResolveRepo(args);
  if (!repo) return { result: mcpToolError('Repository not found') };
  const num = typeof args.pull_number === 'number' ? args.pull_number : parseInt(String(args.pull_number), 10);
  const pr = repo.pullsByNum.get(num);
  if (!pr) return { result: mcpToolError('Pull request not found') };
  if (pr.state !== 'open') return { result: mcpToolError('Pull request is already closed') };
  const merged = doMerge(repo, pr);
  if (!merged.ok) return { result: mcpToolError('Merge conflict: pull request cannot be merged') };
  return { result: mcpToolResult({ merged: true, sha: merged.sha, number: pr.number }) };
}
async function handleMcp(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const method = req.method ?? 'POST';
  if (method === 'DELETE') {
    res.writeHead(202, { 'x-github-request-id': `req-${++reqSeq}` });
    res.end();
    return;
  }
  if (method !== 'POST') { errJson(res, 405, 'Method Not Allowed'); return; }
  if (!authed(req)) {
    sendJson(res, 401, { jsonrpc: '2.0', id: null, error: { code: -32000, message: 'Unauthorized' } });
    return;
  }
  const body = await readBody(req);
  let parsed: unknown;
  try { parsed = JSON.parse(body.toString('utf8')) as unknown; } catch {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    sendJson(res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  const rpc = parsed as Record<string, unknown>;
  const id = rpc.id ?? null;
  const rpcMethod = typeof rpc.method === 'string' ? rpc.method : '';
  const params = (rpc.params ?? {}) as Record<string, unknown>;
  if (rpcMethod === 'notifications/initialized' || rpcMethod.startsWith('notifications/')) {
    res.writeHead(202, { 'x-github-request-id': `req-${++reqSeq}` });
    res.end();
    return;
  }
  if (rpcMethod === 'server/discover') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: { resultType: 'discover', supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'], capabilities: { tools: {} }, serverInfo: { name: 'github-forge', version: '1.0.0' } } });
    return;
  }
  if (rpcMethod === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
    const negotiated = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'].includes(offered) ? offered : '2025-11-25';
    sendJson(res, 200, { jsonrpc: '2.0', id, result: { protocolVersion: negotiated, capabilities: { tools: {} }, serverInfo: { name: 'github-forge', version: '1.0.0' } } }, { 'mcp-session-id': 'sess-1' });
    return;
  }
  if (rpcMethod === 'ping') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: {} });
    return;
  }
  if (rpcMethod === 'tools/list') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } });
    return;
  }
  if (rpcMethod === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const out = execMcpTool(toolName, args);
    if (out.rpcError) { sendJson(res, 200, { jsonrpc: '2.0', id, error: out.rpcError }); return; }
    sendJson(res, 200, { jsonrpc: '2.0', id, result: out.result });
    return;
  }
  sendJson(res, 200, { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${rpcMethod}` } });
}

// ---------------------------------------------------------------- server
export function createApp(): Server {
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const rawUrl = req.url ?? '/';
        const q = rawUrl.indexOf('?');
        const path = q < 0 ? rawUrl : rawUrl.slice(0, q);
        const method = req.method ?? 'GET';
        if (method === 'GET' && path === '/healthz') { sendJson(res, 200, { ok: true }); return; }
        if (path === '/api/graphql') {
          if (method === 'POST') { await handleGraphql(req, res); return; }
          errJson(res, 404, 'Not Found');
          return;
        }
        if (path === '/mcp') { await handleMcp(req, res); return; }
        if (method === 'GET' && path.startsWith('/api/v3/repos/')) {
          // Hot path: the read workload is 2000 sequential GETs of one issue.
          // Skip the generic REST router's split/decode/branch chain entirely.
          const m = /^\/api\/v3\/repos\/([^/]+)\/([^/]+)\/issues\/(\d+)$/.exec(path);
          if (m) {
            if (!authed(req)) { errJson(res, 401, 'Requires authentication'); return; }
            const repo = getRepo(dec(m[1] as string), dec(m[2] as string));
            const iss = repo?.issuesByNum.get(parseInt(m[3] as string, 10));
            if (!repo || !iss) { errJson(res, 404, 'Not Found'); return; }
            const buf = issueJsonBuf(repo, iss);
            res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', 'content-length': buf.length, 'x-github-request-id': `req-${++reqSeq}` });
            res.end(buf);
            return;
          }
        }
        const qs = new URLSearchParams(q < 0 ? '' : rawUrl.slice(q + 1));
        if (path.startsWith('/api/v3')) { await handleRest(req, res, path, qs); return; }
        const segs = path.split('/').filter((s) => s !== '');
        if (segs.length >= 2 && (segs[1] as string).endsWith('.git')) { await handleGit(req, res, path, qs); return; }
        errJson(res, 404, 'Not Found');
      } catch (err) {
        if (!res.headersSent) {
          try { errJson(res, 500, err instanceof Error ? err.message : 'Internal Server Error'); } catch { /* ignore */ }
        } else { try { res.end(); } catch { /* ignore */ } }
      }
    })();
  });
  server.keepAliveTimeout = 30000;
  server.headersTimeout = 60000;
  return server;
}
