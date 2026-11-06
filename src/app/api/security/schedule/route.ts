import { z } from "zod";
import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { parseRepo } from "@/lib/ingest/repo";
import { persist } from "@/lib/persist";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";

const NO_STORE = { "cache-control": "private, no-store" };
const err = (error: string, status: number) => Response.json({ error }, { status, headers: NO_STORE });
const Body = z.object({ repo: z.string().max(200), cadence: z.enum(["daily", "weekly", "off"]) });

async function gate(req: Request, raw: string | null) {
  let repo: string;
  try { const r = parseRepo(raw ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) { return { fail: err((e as Error).message, 400) }; }
  const a = await authorizeRepo(req, repo, { need: "push" }); // scheduling scans is for maintainers
  if (!a.ok) return { fail: err(a.message, a.status) };
  return { repo, a };
}

export async function GET(req: Request) {
  const rl = rateLimit(req, LIMITS.domains);
  if (!rl.ok) return tooMany(rl);
  const g = await gate(req, new URL(req.url).searchParams.get("repo"));
  if (g.fail) return g.fail;
  const configured = !!process.env.CRON_SECRET;
  return withSetCookie(Response.json({ schedule: await persist().getSchedule(g.repo), configured }, { headers: NO_STORE }), g.a.setCookie);
}

export async function PUT(req: Request) {
  const rl = rateLimit(req, LIMITS.write);
  if (!rl.ok) return tooMany(rl);
  const body = Body.safeParse(await req.json().catch(() => null));
  if (!body.success) return err("Bad request.", 400);
  const g = await gate(req, body.data.repo);
  if (g.fail) return g.fail;
  const store = persist();
  if (body.data.cadence === "off") {
    await store.putSchedule(g.repo, null);
    return withSetCookie(Response.json({ schedule: null }, { headers: NO_STORE }), g.a.setCookie);
  }
  const prev = await store.getSchedule(g.repo);
  const next = { ...(prev ?? { enabledBy: g.a.login ?? "unknown", enabledAt: Date.now() }), cadence: body.data.cadence };
  await store.putSchedule(g.repo, next);
  return withSetCookie(Response.json({ schedule: next }, { headers: NO_STORE }), g.a.setCookie);
}
