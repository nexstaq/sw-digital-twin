import { denyBots } from "@/lib/security/bot";
import { LIMITS, rateLimit, tooManySse } from "@/lib/security/ratelimit";
import { authorizeRepo } from "@/lib/auth/viewer";
import { parseRepo } from "@/lib/ingest/repo";
import { runIngest } from "@/lib/ingest/pipeline";
import { persist } from "@/lib/persist";

export const maxDuration = 300;

// Public scans need no account, so cap concurrency per instance.
const MAX_CONCURRENT = 2;
let inFlight = 0;

const sse = (event: unknown) => `data: ${JSON.stringify(event)}\n\n`;

export async function GET(req: Request) {
  const rl = rateLimit(req, LIMITS.scan);
  if (!rl.ok) return tooManySse(rl);
  const bot = await denyBots();
  if (bot) return new Response(`data: ${JSON.stringify({ type: "error", message: "Automated traffic isn't allowed here." })}\n\n`, { status: 403, headers: { "content-type": "text/event-stream" } });
  const url = new URL(req.url);
  const repo = url.searchParams.get("repo") ?? "";
  const ref = url.searchParams.get("ref") ?? undefined;

  // public repos: anyone. Private repos: only a signed-in user GitHub says can read them (then we clone with the App's token).
  let slug: string;
  try { const r = parseRepo(repo); slug = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) {
    return new Response(sse({ type: "error", message: (e as Error).message }), { status: 400, headers: { "content-type": "text/event-stream" } });
  }
  const authz = await authorizeRepo(req, slug);
  if (!authz.ok) return new Response(sse({ type: "error", message: authz.message }), { status: authz.status, headers: { "content-type": "text/event-stream" } });

  if (inFlight >= MAX_CONCURRENT) {
    return new Response(sse({ type: "error", message: "The scanner is busy. Try again in a moment." }), {
      status: 429, headers: { "content-type": "text/event-stream" },
    });
  }
  inFlight++;

  const enc = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const abort = new AbortController();
      req.signal.addEventListener("abort", () => abort.abort());
      try {
        for await (const ev of runIngest({ repo, ref, token: authz.private ? authz.token : undefined, private: authz.private }, abort.signal)) {
          if (req.signal.aborted) break;
          controller.enqueue(enc.encode(sse(ev)));
          // keep "the map at this commit" so history can be replayed against the structure that existed then
          if (ev.type === "done" && ev.commit && ev.graph.nodes.length) {
            await persist().putSnapshot(ev.graph.repo.toLowerCase(), { sha: ev.commit.sha, committedAt: ev.commit.committedAt, createdAt: Date.now(), graph: ev.graph }).catch(() => {});
          }
        }
      } finally {
        inFlight--;
        try { controller.close(); } catch { /* client already left */ }
      }
    },
    cancel() { /* abort handled via req.signal; cleanup runs in runIngest's finally */ },
  });

  const headers = new Headers({ "content-type": "text/event-stream", "cache-control": "no-store, no-transform", connection: "keep-alive" });
  if (authz.setCookie) headers.append("set-cookie", authz.setCookie);
  return new Response(stream, { headers });
}
