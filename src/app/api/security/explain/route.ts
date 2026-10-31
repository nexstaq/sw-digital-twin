import { z } from "zod";
import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { parseRepo } from "@/lib/ingest/repo";
import { persist } from "@/lib/persist";
import { denyBots } from "@/lib/security/bot";
import { explainFinding } from "@/lib/security/explain";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";

export const maxDuration = 60;
const Body = z.object({ repo: z.string().max(200), findingId: z.string().regex(/^[0-9a-f]{8,32}$/) });
const NO_STORE = { "cache-control": "private, no-store" };

/**
 * A plain-English explanation of one stored finding, written by a model from the finding's own facts (never source code or a secret).
 * Maintainers only. A private repository never uses a free-tier model. Costs tokens, so it is rate limited and bot-checked.
 */
export async function POST(req: Request) {
  const rl = rateLimit(req, LIMITS.explain);
  if (!rl.ok) return tooMany(rl);
  const bot = await denyBots();
  if (bot) return bot;
  const raw = await req.json().catch(() => null);
  const body = Body.safeParse(raw);
  if (!body.success) return Response.json({ error: "Bad request." }, { status: 400, headers: NO_STORE });
  let repo: string;
  try { const r = parseRepo(body.data.repo); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) { return Response.json({ error: (e as Error).message }, { status: 400, headers: NO_STORE }); }

  const a = await authorizeRepo(req, repo, { need: "push" });
  if (!a.ok) return Response.json({ error: a.message }, { status: a.status, headers: NO_STORE });
  const finding = (await persist().getFindings(repo))?.findings.find((f) => f.id === body.data.findingId);
  if (!finding) return Response.json({ error: "No such finding. Scan again, then try again." }, { status: 404, headers: NO_STORE });

  const result = await explainFinding(finding, { private: a.private, signal: req.signal });
  return withSetCookie(Response.json(result, { headers: NO_STORE }), a.setCookie);
}
