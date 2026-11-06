import { z } from "zod";
import { MODELS, VIEWS, modelFor, validChoice } from "@/lib/access/views";
import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { parseRepo } from "@/lib/ingest/repo";
import { persist } from "@/lib/persist";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";

const NO_STORE = { "cache-control": "private, no-store" };
const err = (error: string, status: number) => Response.json({ error }, { status, headers: NO_STORE });
const Body = z.object({ repo: z.string().max(200), view: z.string().max(40), model: z.string().max(40) });

/** Changing who can see a repo is for maintainers (push access), checked with the caller's own GitHub token. Never relaxed by a setting. */
async function gate(req: Request, raw: string | null) {
  let repo: string;
  try { const r = parseRepo(raw ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) { return { fail: err((e as Error).message, 400) }; }
  const a = await authorizeRepo(req, repo, { need: "push" });
  if (!a.ok) return { fail: err(a.message, a.status) };
  return { repo, a };
}

const describe = (settings: Awaited<ReturnType<ReturnType<typeof persist>["getAccess"]>>) => ({
  models: Object.entries(MODELS).map(([id, m]) => ({ id, label: m.label, short: m.short, description: m.description })),
  views: VIEWS.map((v) => ({ id: v.id, label: v.label, covers: v.covers, default: v.default, allowed: v.allowed, fixedBecause: v.fixedBecause, model: modelFor(settings, v.id) })),
});

export async function GET(req: Request) {
  const rl = rateLimit(req, LIMITS.domains);
  if (!rl.ok) return tooMany(rl);
  const g = await gate(req, new URL(req.url).searchParams.get("repo"));
  if (g.fail) return g.fail;
  return withSetCookie(Response.json(describe(await persist().getAccess(g.repo)), { headers: NO_STORE }), g.a.setCookie);
}

export async function PUT(req: Request) {
  const rl = rateLimit(req, LIMITS.write);
  if (!rl.ok) return tooMany(rl);
  const body = Body.safeParse(await req.json().catch(() => null));
  if (!body.success) return err("Bad request.", 400);
  const g = await gate(req, body.data.repo);
  if (g.fail) return g.fail;
  const choice = validChoice(body.data.view, body.data.model);
  if (!choice.ok) return err(choice.reason, 400);
  const store = persist();
  const next = { ...(await store.getAccess(g.repo)), [choice.view]: choice.model };
  // keep the stored object to real choices: picking the default again just removes it
  if (VIEWS.find((v) => v.id === choice.view)!.default === choice.model) delete next[choice.view];
  await store.putAccess(g.repo, next);
  return withSetCookie(Response.json(describe(next), { headers: NO_STORE }), g.a.setCookie);
}
