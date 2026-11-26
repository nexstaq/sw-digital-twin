import { z } from "zod";
import { appOrigin } from "@/lib/auth/origin";
import { seal, secretOk } from "@/lib/auth/session";
import { parseRepo } from "@/lib/ingest/repo";
import { persist } from "@/lib/persist";
import { verifyActionsToken } from "@/lib/security/oidc";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";
import { PROFILES, buildPlan } from "@/lib/sim/ci/plan";
import { stagingOrigin } from "@/lib/sim/roe";

const NO_STORE = { "cache-control": "private, no-store" };
const err = (error: string, status: number) => Response.json({ error }, { status, headers: NO_STORE });

const Body = z.strictObject({ url: stagingOrigin, profile: z.enum(PROFILES), confirmed: z.literal(true) });

/**
 * Part one of an authorised external run (X9): a customer's own CI workflow (never a browser, never a person) asks which
 * requests it may make against its own staging site. Nothing here sends a request anywhere: it decides, logs the decision,
 * and hands back a short-lived, tamper-evident plan the workflow carries to the actual requests and back to `ci-report`.
 * "Our servers never send simulation traffic to third parties" (X9): the HTTP calls happen on the runner, from this plan.
 */
export async function POST(req: Request) {
  const rl = rateLimit(req, LIMITS.ciPlan);
  if (!rl.ok) return tooMany(rl);
  if (!secretOk(process.env.SESSION_SECRET)) return err("This is not configured on this deployment.", 503);

  let repo: string;
  try { const r = parseRepo(new URL(req.url).searchParams.get("repo") ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) {
    return err((e as Error).message, 400);
  }

  const bearer = /^Bearer\s+(\S+)$/i.exec(req.headers.get("authorization") ?? "")?.[1];
  if (!bearer) return err("This needs a GitHub Actions OIDC token.", 401);
  const v = await verifyActionsToken(bearer, { audience: appOrigin(req) });
  if (!v.ok) return err(`That CI token was refused (${v.reason}).`, 401);
  if (v.claims.repository.toLowerCase() !== repo) return err("That CI token belongs to a different repository.", 403);

  const body = Body.safeParse(await req.json().catch(() => null));
  if (!body.success) return err("Name an https staging origin, one of the known profiles, and confirm ownership.", 400);

  const store = persist();
  const set = await store.getFindings(repo);
  if (!set) return err("Run a security scan first, then generate the simulation workflow.", 409);
  const latest = (await store.listSnapshots(repo)).at(-1);
  const snap = latest ? await store.getSnapshot(repo, latest.sha) : null;
  if (!snap) return err("Map the repository first: the plan is built from its map.", 409);

  const now = Date.now();
  const plan = await buildPlan({
    repo, url: body.data.url, profile: body.data.profile, sha: set.sha, graph: snap.graph, set,
    approvedBy: v.claims.actor ?? v.claims.repository, now: () => now,
  });

  const token = seal({ v: 1, repo, url: body.data.url, profile: body.data.profile, controlPath: plan.controlPath, routes: plan.routes.map((r) => r.path), exp: now + 35 * 60_000 }, process.env.SESSION_SECRET!);
  return Response.json({ runId: plan.runId, controlPath: plan.controlPath, routes: plan.routes.map((r) => r.path), notes: plan.notes, token }, { headers: NO_STORE });
}
