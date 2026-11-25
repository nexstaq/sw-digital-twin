import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { parseRepo } from "@/lib/ingest/repo";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";
import { patchFor } from "@/lib/sim/whitebox/run";

const NO_STORE = { "cache-control": "private, no-store" };

/**
 * The patch the simulation proposed for one finding, as a diff to read. It is made again from the file at the scanned commit, with the
 * caller's own access, and never stored: a diff contains source code. Nothing is ever applied or pushed from here.
 */
export async function GET(req: Request) {
  const rl = rateLimit(req, LIMITS.snippet);
  if (!rl.ok) return tooMany(rl);
  const url = new URL(req.url);
  let repo: string;
  try { const r = parseRepo(url.searchParams.get("repo") ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 400, headers: NO_STORE });
  }
  const id = url.searchParams.get("finding") ?? "";
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(id)) return Response.json({ error: "Bad request." }, { status: 400, headers: NO_STORE });
  const a = await authorizeRepo(req, repo, { need: "push" });
  if (!a.ok) return Response.json({ error: a.message }, { status: a.status, headers: NO_STORE });
  const out = await patchFor(repo, id, a.token, { signal: req.signal });
  if (!out.ok) return Response.json({ error: out.error }, { status: out.status, headers: NO_STORE });
  return withSetCookie(Response.json({ diff: out.diff, kind: out.kind, retest: out.retest, note: "Shown for you to read. Nothing was changed, and nothing is stored." }, { headers: NO_STORE }), a.setCookie);
}
