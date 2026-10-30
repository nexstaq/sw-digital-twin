import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { parseRepo } from "@/lib/ingest/repo";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";
import { loadView, viewVerdict } from "@/lib/share/view";

/**
 * GO / HOLD / NO-GO for one repo, as JSON, for the browser extension. Same access rule as everything else (`authorizeRepo`):
 * public repos are open, private ones need the caller's signed-in session. No CORS headers on purpose: only the extension's
 * background worker (which has host permission) and our own pages can read it, never another website.
 */
export async function GET(req: Request) {
  const rl = rateLimit(req, LIMITS.verdict);
  if (!rl.ok) return tooMany(rl);
  let repo: string;
  try { const r = parseRepo(new URL(req.url).searchParams.get("repo") ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 400 });
  }
  const a = await authorizeRepo(req, repo);
  if (!a.ok) return Response.json({ error: a.message }, { status: a.status, headers: { "cache-control": "private, no-store" } });
  const v = await loadView(repo, { token: a.token });
  const body = v.ok ? { state: "ok", private: a.private, ...pick(viewVerdict(v)) } : { state: "unmapped", private: a.private };
  return withSetCookie(Response.json(body, { headers: { "cache-control": "private, no-store" } }), a.setCookie);
}

const pick = (v: ReturnType<typeof viewVerdict>) => ({ word: v.word, tone: v.tone, why: v.why });
