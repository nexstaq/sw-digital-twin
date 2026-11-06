import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { parseRepo } from "@/lib/ingest/repo";
import { denyBots } from "@/lib/security/bot";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";
import { scanAndStore } from "@/lib/security/run-scan";

export const maxDuration = 120;

const MAX_CONCURRENT = 2;
let inFlight = 0;
const NO_STORE = { "cache-control": "private, no-store" };

/**
 * Runs the security analyzers over the repo's default branch and stores the findings. Needs PUSH access: a list of a project's
 * vulnerabilities is far more sensitive than its architecture, so it is for maintainers, not for everyone who can read the code.
 */
export async function POST(req: Request) {
  const rl = rateLimit(req, LIMITS.secscan);
  if (!rl.ok) return tooMany(rl);
  const bot = await denyBots();
  if (bot) return bot;
  let repo: string;
  try { const r = parseRepo(new URL(req.url).searchParams.get("repo") ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 400 });
  }
  const a = await authorizeRepo(req, repo, { need: "push" });
  if (!a.ok) return Response.json({ error: a.message }, { status: a.status, headers: NO_STORE });
  if (inFlight >= MAX_CONCURRENT) return Response.json({ error: "The scanner is busy. Try again in a moment." }, { status: 429, headers: NO_STORE });

  inFlight++;
  try {
    const set = await scanAndStore(repo, a.token, req.signal);
    return withSetCookie(Response.json(set, { headers: NO_STORE }), a.setCookie);
  } catch (e) {
    return Response.json({ error: e instanceof Error ? e.message : "The security scan failed." }, { status: 502, headers: NO_STORE });
  } finally {
    inFlight--;
  }
}
