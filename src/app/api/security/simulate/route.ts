import { z } from "zod";
import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { parseRepo } from "@/lib/ingest/repo";
import { denyBots } from "@/lib/security/bot";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";
import { killRegistry } from "@/lib/sim/agent/killswitch";
import { simulateAndStore } from "@/lib/sim/whitebox/run";

export const maxDuration = 60;

const NO_STORE = { "cache-control": "private, no-store" };
const Body = z.strictObject({ source: z.boolean().optional() });
const MAX_CONCURRENT = 2;
let inFlight = 0;
const running = new Set<string>();

function repoOf(req: Request): string | Response {
  try { const r = parseRepo(new URL(req.url).searchParams.get("repo") ?? ""); return `${r.owner}/${r.name}`.toLowerCase(); } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 400, headers: NO_STORE });
  }
}

/**
 * "Verify by simulation": runs the white-box agent over the saved map and the latest scan and stores its verdicts on the findings.
 * Needs PUSH access, like the scan: it concerns a project's weaknesses. It touches nothing real: the agent works on a simulated copy.
 * `{"source": true}` additionally lets it read a few lines around each finding (with the caller's own access) to look for mitigations
 * and propose patches. That is off unless asked for, and nothing it reads is stored.
 */
export async function POST(req: Request) {
  const rl = rateLimit(req, LIMITS.simulate);
  if (!rl.ok) return tooMany(rl);
  const bot = await denyBots();
  if (bot) return bot;
  const repo = repoOf(req);
  if (typeof repo !== "string") return repo;
  let body: z.infer<typeof Body> = {};
  const text = await req.text();
  if (text.trim()) {
    let json: unknown;
    try { json = JSON.parse(text); } catch { return Response.json({ error: "Bad request." }, { status: 400, headers: NO_STORE }); }
    const p = Body.safeParse(json);
    if (!p.success) return Response.json({ error: "Bad request." }, { status: 400, headers: NO_STORE });
    body = p.data;
  }
  const a = await authorizeRepo(req, repo, { need: "push" });
  if (!a.ok) return Response.json({ error: a.message }, { status: a.status, headers: NO_STORE });
  if (running.has(repo)) return Response.json({ error: "A simulation is already running for this repository." }, { status: 409, headers: NO_STORE });
  if (inFlight >= MAX_CONCURRENT) return Response.json({ error: "The simulator is busy. Try again in a moment." }, { status: 429, headers: NO_STORE });

  inFlight++; running.add(repo);
  try {
    const out = await simulateAndStore(repo, a.token, { source: body.source === true, signal: req.signal });
    if (!out.ok) return Response.json({ error: out.error }, { status: out.status, headers: NO_STORE });
    return withSetCookie(Response.json(out.set, { headers: NO_STORE }), a.setCookie);
  } catch (e) {
    return Response.json({ error: e instanceof Error ? e.message : "The simulation failed." }, { status: 500, headers: NO_STORE });
  } finally {
    inFlight--; running.delete(repo);
  }
}

/** The kill switch for this repository: stops any simulation running for it, and tears down what it started. */
export async function DELETE(req: Request) {
  const rl = rateLimit(req, LIMITS.write);
  if (!rl.ok) return tooMany(rl);
  const repo = repoOf(req);
  if (typeof repo !== "string") return repo;
  const a = await authorizeRepo(req, repo, { need: "push" });
  if (!a.ok) return Response.json({ error: a.message }, { status: a.status, headers: NO_STORE });
  const stopped = await killRegistry().killRepo(repo, "stopped by a maintainer");
  return withSetCookie(Response.json({ stopped }, { headers: NO_STORE }), a.setCookie);
}
