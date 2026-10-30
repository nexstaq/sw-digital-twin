import { z } from "zod";
import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { appOrigin } from "@/lib/auth/origin";
import { parseRepo } from "@/lib/ingest/repo";
import { persist } from "@/lib/persist";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";
import { hashSecret, newSecret, newShareId } from "@/lib/share/token";

const MAX_LIVE = 20;
const slugOf = (raw: string | null) => { const r = parseRepo(raw ?? ""); return `${r.owner}/${r.name}`.toLowerCase(); };
const Create = z.object({ label: z.string().trim().max(60).optional() });
const strip = (s: { id: string; label?: string; createdBy: string; createdAt: number; revokedAt?: number }) => ({ id: s.id, label: s.label, createdBy: s.createdBy, createdAt: s.createdAt, revokedAt: s.revokedAt });

/** Managing read-only share links needs push access: a link shows the map without signing in, so only maintainers hand them out. */
async function gate(req: Request) {
  const rl = rateLimit(req, LIMITS.write);
  if (!rl.ok) return { fail: tooMany(rl) };
  let repo: string;
  try { repo = slugOf(new URL(req.url).searchParams.get("repo")); } catch (e) { return { fail: Response.json({ error: (e as Error).message }, { status: 400 }) }; }
  const a = await authorizeRepo(req, repo, { need: "push" });
  if (!a.ok) return { fail: Response.json({ error: a.message }, { status: a.status }) };
  return { repo, a };
}

export async function GET(req: Request) {
  const g = await gate(req);
  if (g.fail) return g.fail;
  return withSetCookie(Response.json({ shares: (await persist().listShares(g.repo)).map(strip) }), g.a.setCookie);
}

/** The link comes back once. Only its hash is stored, so a lost link cannot be recovered, only replaced. */
export async function POST(req: Request) {
  const g = await gate(req);
  if (g.fail) return g.fail;
  const parsed = Create.safeParse(await req.json().catch(() => ({})));
  if (!parsed.success) return Response.json({ error: "Bad request." }, { status: 400 });
  const store = persist();
  if ((await store.listShares(g.repo)).filter((s) => !s.revokedAt).length >= MAX_LIVE) return Response.json({ error: `At most ${MAX_LIVE} active links. Revoke one first.` }, { status: 409 });
  const secret = newSecret();
  const share = { id: newShareId(), hash: hashSecret(secret), label: parsed.data.label || undefined, createdBy: g.a.login ?? "unknown", createdAt: Date.now() };
  await store.addShare(g.repo, share);
  const [owner, name] = g.repo.split("/");
  const url = `${appOrigin(req)}/s/${owner}/${name}/${secret}`;
  return withSetCookie(Response.json({ share: strip(share), url, badge: `${appOrigin(req)}/api/badge/${owner}/${name}?t=${secret}` }, { status: 201, headers: { "cache-control": "no-store" } }), g.a.setCookie);
}

export async function DELETE(req: Request) {
  const g = await gate(req);
  if (g.fail) return g.fail;
  const id = new URL(req.url).searchParams.get("id") ?? "";
  if (!/^[0-9a-f]{12}$/.test(id)) return Response.json({ error: "Bad request." }, { status: 400 });
  const ok = await persist().revokeShare(g.repo, id, Date.now());
  return withSetCookie(ok ? Response.json({ ok: true }) : Response.json({ error: "No such active link." }, { status: 404 }), g.a.setCookie);
}
