# github-forge-r4

A standalone GitHub-compatible git forge in one Node process: git smart HTTP
(upload-pack protocol v2, receive-pack v0), REST v3, GraphQL v4 and MCP
(Streamable HTTP, revision 2026-07-28), all served from a single in-memory
store. No UI, no database, no git binary, no network — Node 22 standard
library only.

![github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)
![rank](https://make.fun/badge/github-core-clone-01/Mansyur0523/github-forge-r4/rank.svg)
![reward](https://make.fun/badge/github-core-clone-01/Mansyur0523/github-forge-r4/reward.svg)

- Bounty: https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01
- Leaderboard: https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01

## Run it

```sh
node /bot/main.ts
```

The entry binds an ephemeral port, registers it with the suite at
`$MAKEFUN_ENV_URL`, serves until the suite answers `/done`, then exits 0.

## Surfaces

| Route | What it is |
| --- | --- |
| `GET /healthz` | 200 `{"ok":true}` boot probe |
| `/<owner>/<repo>.git/...` | git smart HTTP: `info/refs`, `git-upload-pack` (v2), `git-receive-pack` (v0) |
| `/api/v3/...` | GitHub REST v3: repositories, branches, commits, contents, issues, comments, labels, pull requests, files, merges |
| `POST /api/graphql` | GitHub GraphQL v4: the documents `gh` and `github-mcp-server` send |
| `POST /mcp` | Model Context Protocol over Streamable HTTP: `server/discover`, `initialize`, `tools/list`, `tools/call` |

## Design

- One in-memory store: objects are content-addressed by SHA-1 exactly as git
  computes them; refs, issues, pull requests and labels live in Maps, so the
  hot paths (issue reads, pushes, shallow clones) never touch disk.
- Deterministic: no clocks or randomness in stored state — timestamps derive
  from fixed counters, so a replay leaves the same state.
- Fast paths: git advertisements, ls-refs and fetch responses are cached per
  repository and invalidated only when a ref moves; issue reads serve a
  pre-serialised JSON body; packs are built with plain (undeltified) objects
  and zlib level 1.

## Layout

- `main.ts`: the entry/env lifecycle (bind, register, poll `/done`).
- `app.ts`: the whole forge — object store, packfile codec, git protocol,
  REST v3, GraphQL v4 and MCP.
- `LICENSE`: MIT.
