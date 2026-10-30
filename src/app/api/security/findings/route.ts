import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { parseRepo } from "@/lib/ingest/repo";
import { persist } from "@/lib/persist";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";

/** The latest stored security scan, for people with push access. Never reachable through a share link or the badge. */
export async function GET(req: Request) {
  const rl = rateLimit(req, LIMITS.write);
  if (!rl.ok) return tooMany(rl);
  let repo: string;
  try { const r = parseRepo(new URL(req.url).searchParams.get("repo") ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 400 });
  }
  const a = await authorizeRepo(req, repo, { need: "push" });
  if (!a.ok) return Response.json({ error: a.message }, { status: a.status, headers: { "cache-control": "private, no-store" } });
  return withSetCookie(Response.json({ set: await persist().getFindings(repo) }, { headers: { "cache-control": "private, no-store" } }), a.setCookie);
}
