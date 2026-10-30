import { z } from "zod";
import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { parseRepo } from "@/lib/ingest/repo";
import { persist } from "@/lib/persist";

const slugOf = (raw: string | null) => { const r = parseRepo(raw ?? ""); return `${r.owner}/${r.name}`.toLowerCase(); };
const Body = z.object({ mappings: z.record(z.string().max(300), z.string().max(300)).refine((m) => Object.keys(m).length <= 500) });

/** Confirmed signal -> node mappings, shared by everyone who can see the repo. Read: read access. Write: push access. */
export async function GET(req: Request) {
  let repo: string;
  try { repo = slugOf(new URL(req.url).searchParams.get("repo")); } catch (e) { return Response.json({ error: (e as Error).message }, { status: 400 }); }
  const a = await authorizeRepo(req, repo);
  if (!a.ok) return Response.json({ error: a.message }, { status: a.status });
  return withSetCookie(Response.json({ mappings: await persist().getMappings(repo), canEdit: !!a.access?.push }), a.setCookie);
}

export async function PUT(req: Request) {
  let repo: string;
  try { repo = slugOf(new URL(req.url).searchParams.get("repo")); } catch (e) { return Response.json({ error: (e as Error).message }, { status: 400 }); }
  const a = await authorizeRepo(req, repo, { need: "push" });
  if (!a.ok) return Response.json({ error: a.message }, { status: a.status });
  const raw = await req.text();
  if (raw.length > 100_000) return Response.json({ error: "Too large." }, { status: 413 });
  let body;
  try { body = Body.safeParse(JSON.parse(raw)); } catch { body = null; }
  if (!body?.success) return Response.json({ error: "Bad request." }, { status: 400 });
  await persist().putMappings(repo, body.data.mappings);
  return withSetCookie(Response.json({ ok: true }), a.setCookie);
}
