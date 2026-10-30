import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { parseRepo } from "@/lib/ingest/repo";
import { persist } from "@/lib/persist";

/** Stored maps ("what the system looked like at this commit"). Private repos: only for users GitHub says can read them. */
export async function GET(req: Request) {
  const url = new URL(req.url);
  let repo: string;
  try { const r = parseRepo(url.searchParams.get("repo") ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 400 });
  }
  const a = await authorizeRepo(req, repo);
  if (!a.ok) return Response.json({ error: a.message }, { status: a.status });
  const sha = url.searchParams.get("sha");
  if (sha) {
    const snap = await persist().getSnapshot(repo, sha);
    return withSetCookie(snap ? Response.json(snap) : Response.json({ error: "No such snapshot." }, { status: 404 }), a.setCookie);
  }
  return withSetCookie(Response.json({ snapshots: await persist().listSnapshots(repo) }), a.setCookie);
}
