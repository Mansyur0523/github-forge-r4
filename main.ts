// The entrypoint is only a bridge between the forge in app.ts and the trial
// env: it puts the server on a port the OS picks, hands that port to the env,
// and then waits until the env says the trial is over.
//
// The exchange, step by step:
//
//   1. MAKEFUN_ENV_URL tells us where the env lives. With no value there is
//      no env to talk to, so we stop at once with a nonzero exit.
//   2. The server binds port 0, letting the kernel choose. Port 8080 belongs
//      to the env, so we never ask for it.
//   3. POST /register carries the chosen port. The env notes where the call
//      came from plus that port, and dials us there from then on. Whoever
//      registers first wins; a 409 means someone else already did, and we
//      just keep waiting like any other entry.
//   4. GET /done is asked again and again until the env answers
//      {"done": true}. Each answer comes back at once, so this is a poll, not
//      a held-open request. A failed or slow ask is retried after a pause
//      that grows with each failure, up to a cap; the process never leaves
//      before the env says so.
//   5. The server is closed and the process leaves with code 0.
//
// Nothing else lives here: no package import, no Node built-in, no model call.

import { createApp } from "./app.ts";

/** One env call may run this long before it is dropped and tried again. */
const CALL_LIMIT_MS = 30_000;
/** The pause after the first failed call, and the longest pause allowed. */
const FIRST_WAIT_MS = 250;
const LONGEST_WAIT_MS = 2_000;

/** The env's origin with any trailing slashes stripped off. */
function readEnvOrigin(): string {
  let origin = process.env.MAKEFUN_ENV_URL ?? "";
  while (origin.endsWith("/")) origin = origin.slice(0, -1);
  return origin;
}

const ENV_ORIGIN = readEnvOrigin();
if (ENV_ORIGIN === "") {
  process.stderr.write("[entry] MAKEFUN_ENV_URL is missing, so there is no env to announce to\n");
  process.exit(1);
}

function wait(ms: number): Promise<void> {
  return new Promise((wake) => setTimeout(wake, ms));
}

/** The pause after `failures` failed calls: doubling from FIRST_WAIT_MS, capped. */
function waitAfter(failures: number): number {
  let pause = FIRST_WAIT_MS;
  for (let i = 0; i < failures && pause < LONGEST_WAIT_MS; i += 1) pause *= 2;
  return pause;
}

/** A register answer the env means as final: the entry is out, not retried. */
class RegisterRefused extends Error {}

/**
 * Tell the env which port we bound. 200 means it took the port; 409 means a
 * first registration already won and there is nothing to fix. 400 and 405
 * are contract rejections and end the program; anything else (a network
 * failure, another status, a call that ran over its limit) is retried, since
 * the env may still be starting.
 */
async function announcePort(port: number): Promise<void> {
  let failures = 0;
  while (true) {
    let reply: Response | null = null;
    try {
      reply = await fetch(`${ENV_ORIGIN}/register`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(CALL_LIMIT_MS),
      });
    } catch {
      // No answer at all: the env is not up yet, or the call timed out.
    }
    if (reply !== null) {
      if (reply.status === 200 || reply.status === 409) return;
      if (reply.status === 400 || reply.status === 405) {
        const detail = await reply.text().catch(() => "");
        throw new RegisterRefused(`register refused, HTTP ${reply.status}: ${detail}`);
      }
    }
    await wait(waitAfter(failures));
    failures += 1;
  }
}

/** Ask GET /done until the env answers {"done": true}; never leave before that. */
async function waitForEnvDone(): Promise<void> {
  let failures = 0;
  while (true) {
    try {
      const reply = await fetch(`${ENV_ORIGIN}/done`, { signal: AbortSignal.timeout(CALL_LIMIT_MS) });
      if (reply.ok) {
        const payload = (await reply.json()) as { done?: unknown };
        if (payload.done === true) return;
      }
    } catch {
      // The env is not answering yet, or the ask timed out: not done, ask again.
    }
    await wait(waitAfter(failures));
    failures += 1;
  }
}

/** Bind the port, announce it, then wait for the env: the whole life of the process. */
async function run(): Promise<void> {
  const server = createApp();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, resolve);
  });
  const bound = server.address();
  if (bound === null || typeof bound === "string") {
    throw new Error("server bound no TCP port");
  }
  process.stdout.write(`[entry] serving on port ${bound.port}\n`);

  await announcePort(bound.port);
  process.stdout.write("[entry] port announced; waiting for the env to finish\n");

  await waitForEnvDone();
  server.close();
  process.stdout.write("[entry] env done, shutting down\n");
}

run().then(
  () => process.exit(0),
  (err: unknown) => {
    process.stderr.write(`[entry] ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  },
);
