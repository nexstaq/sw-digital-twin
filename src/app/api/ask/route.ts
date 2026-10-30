import { z } from "zod";
import { askAgent, explainNode } from "@/lib/ask/agent";
import { DigestSchema, fromDigest } from "@/lib/ask/digest";
import { isPublicRepo } from "@/lib/github/signals";
import { denyBots } from "@/lib/security/bot";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";

export const maxDuration = 60;

const Body = z.discriminatedUnion("mode", [
  z.object({ mode: z.literal("query"), question: z.string().trim().min(1).max(300), digest: DigestSchema }),
  z.object({ mode: z.literal("explain"), question: z.string().trim().min(1).max(300), nodeId: z.string().max(300), digest: DigestSchema }),
]);

// Every call can cost model tokens: cap per client (see ratelimit.ts) and concurrency per instance.
const MAX_CONCURRENT = 6, MAX_BYTES = 400_000;
let inFlight = 0;

/** Free-form questions about the graph (⌘K fallback) and "ask AI about this node". Returns what to highlight, not an essay. */
export async function POST(req: Request) {
  const rl = rateLimit(req, LIMITS.ask);
  if (!rl.ok) return tooMany(rl);
  const bot = await denyBots();
  if (bot) return bot;
  if (inFlight >= MAX_CONCURRENT) return Response.json({ ok: false, message: "Busy. Try again in a moment." }, { status: 429 });

  const raw = await req.text();
  if (raw.length > MAX_BYTES) return Response.json({ ok: false, message: "That system is too large to ask about." }, { status: 413 });
  let parsed;
  try { parsed = Body.safeParse(JSON.parse(raw)); } catch { parsed = null; }
  if (!parsed?.success) return Response.json({ ok: false, message: "Bad request." }, { status: 400 });

  inFlight++;
  try {
    const g = fromDigest(parsed.data.digest);
    // anything we cannot prove is public is treated as private: it may only use a gateway model, never a free dev key
    const isPrivate = !(await isPublicRepo(g.repo).catch(() => false));
    if (parsed.data.mode === "explain") return Response.json(await explainNode(g, parsed.data.nodeId, parsed.data.question, { signal: req.signal, private: isPrivate }));
    return Response.json(await askAgent(g, parsed.data.question, { signal: req.signal, private: isPrivate }));
  } finally {
    inFlight--;
  }
}
