import { authorizeRepo } from "@/lib/auth/viewer";
import { GitHubError } from "@/lib/github/api";
import { nextPoke } from "@/lib/github/bus";
import { getSignals } from "@/lib/github/signals";
import { parseRepo } from "@/lib/ingest/repo";
import { LIMITS, rateLimit, tooManySse } from "@/lib/security/ratelimit";

export const maxDuration = 300;

const POLL_MS = 20_000; // fallback cadence when no webhook arrives
const SESSION_MS = 280_000; // end before maxDuration; EventSource reconnects on its own
const MAX_STREAMS = 60;
let open = 0;

const sse = (event: unknown) => `data: ${JSON.stringify(event)}\n\n`;
const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((res) => { const t = setTimeout(res, ms); signal.addEventListener("abort", () => { clearTimeout(t); res(); }, { once: true }); });

/** Live health feed for one repo: current signals now, then again whenever GitHub tells us (webhook) or every POLL_MS. */
export async function GET(req: Request) {
  const rl = rateLimit(req, LIMITS.stream);
  if (!rl.ok) return tooManySse(rl);
  let repo: string;
  try { const r = parseRepo(new URL(req.url).searchParams.get("repo") ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) {
    return new Response(sse({ type: "error", fatal: true, message: (e as Error).message }), { status: 400, headers: { "content-type": "text/event-stream" } });
  }
  if (open >= MAX_STREAMS) {
    return new Response(sse({ type: "error", message: "Too many live viewers right now. Retrying…" }), { status: 429, headers: { "content-type": "text/event-stream" } });
  }
  // authorise BEFORE reading anything: private repos need a signed-in user that GitHub says can read them
  const authz = await authorizeRepo(req, repo);
  if (!authz.ok) return new Response(sse({ type: "error", fatal: true, message: authz.message }), { status: authz.status, headers: { "content-type": "text/event-stream" } });
  open++;

  const enc = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const abort = new AbortController();
      const stop = () => abort.abort();
      req.signal.addEventListener("abort", stop);
      const send = (ev: unknown) => { try { controller.enqueue(enc.encode(sse(ev))); } catch { stop(); } };
      const until = Date.now() + SESSION_MS;
      let last = "";
      let force = false;

      try {
        while (!abort.signal.aborted && Date.now() < until) {
          try {
            const signals = await getSignals(repo, { force, token: authz.token });
            const { fetchedAt, ...stable } = signals;
            const sig = JSON.stringify(stable);
            if (sig !== last) { last = sig; send({ type: "signals", signals }); }
            else send({ type: "tick", fetchedAt });
          } catch (e) {
            const fatal = e instanceof GitHubError && e.fatal;
            send({ type: "error", fatal, message: e instanceof Error ? e.message : "Could not reach GitHub.", retryAt: e instanceof GitHubError ? e.retryAt : undefined });
            if (fatal) return;
            await sleep(e instanceof GitHubError && e.retryAt ? Math.min(Math.max(e.retryAt - Date.now(), 5_000), 120_000) : 30_000, abort.signal);
          }
          const woke = new AbortController();
          const onAbort = () => woke.abort();
          abort.signal.addEventListener("abort", onAbort, { once: true });
          const poked = nextPoke(repo, woke.signal).then(() => true);
          const timed = sleep(POLL_MS, woke.signal).then(() => false);
          force = await Promise.race([poked, timed]);
          woke.abort(); // release whichever side lost
          abort.signal.removeEventListener("abort", onAbort);
        }
      } finally {
        open--;
        req.signal.removeEventListener("abort", stop);
        try { controller.close(); } catch { /* client already left */ }
      }
    },
  });
  const headers = new Headers({ "content-type": "text/event-stream", "cache-control": "no-store, no-transform", connection: "keep-alive" });
  if (authz.setCookie) headers.append("set-cookie", authz.setCookie);
  return new Response(stream, { headers });
}
