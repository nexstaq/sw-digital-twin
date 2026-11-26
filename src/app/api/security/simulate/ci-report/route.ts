import { z } from "zod";
import { appOrigin } from "@/lib/auth/origin";
import { open, secretOk } from "@/lib/auth/session";
import { parseRepo } from "@/lib/ingest/repo";
import { persist } from "@/lib/persist";
import { byPriority } from "@/lib/security/map";
import { verifyActionsToken } from "@/lib/security/oidc";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";
import type { FindingSet } from "@/lib/security/types";
import { refreshTrend } from "@/lib/security/trend";
import { applyReport } from "@/lib/sim/ci/apply";
import { PROFILES } from "@/lib/sim/ci/plan";

const NO_STORE = { "cache-control": "private, no-store" };
const err = (error: string, status: number) => Response.json({ error }, { status, headers: NO_STORE });

const Token = z.object({ v: z.literal(1), repo: z.string(), url: z.string(), profile: z.enum(PROFILES), controlPath: z.string(), routes: z.array(z.string()), exp: z.number() });
const Body = z.strictObject({
  token: z.string().max(4000),
  controlStatus: z.number().int(), controlBytes: z.number().int().nonnegative(),
  observations: z.array(z.strictObject({ path: z.string().max(512), status: z.number().int(), bytes: z.number().int().nonnegative() })).max(200),
});

/**
 * Part two of an authorised external run (X9): what the customer's own CI runner says it saw, after making exactly the
 * requests `ci-plan` authorised. The plan is trusted because it is sealed (AES-256-GCM, the same mechanism that seals a
 * session cookie), never because the runner says so: a tampered or expired token, or a reported route that was never on
 * the list, is rejected rather than scored. This never makes a request itself either.
 */
export async function POST(req: Request) {
  const rl = rateLimit(req, LIMITS.ciReport);
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
  if (!body.success) return err("That report is not well formed.", 400);

  const sealed = open<unknown>(body.data.token, process.env.SESSION_SECRET!);
  const plan = sealed ? Token.safeParse(sealed) : null;
  if (!plan?.success) return err("That plan is invalid or was tampered with.", 401);
  if (plan.data.repo !== repo) return err("That plan belongs to a different repository.", 403);
  if (plan.data.exp < Date.now()) return err("That plan has expired. Ask the workflow to request a new one.", 401);

  const store = persist();
  const prev: FindingSet | null = await store.getFindings(repo);
  if (!prev) return err("Run a security scan first.", 409);
  const latest = (await store.listSnapshots(repo)).at(-1);
  const snap = latest ? await store.getSnapshot(repo, latest.sha) : null;
  if (!snap) return err("Map the repository first.", 409);

  const result = applyReport({
    url: plan.data.url, profile: plan.data.profile, sha: prev.sha, graph: snap.graph, set: prev,
    controlStatus: body.data.controlStatus, controlBytes: body.data.controlBytes,
    observations: body.data.observations, authorizedPaths: plan.data.routes,
  });

  const kept = prev.findings.filter((f) => !(f.detail.source === "ci-runner" && f.path.startsWith(plan.data.url)));
  const next = refreshTrend({
    ...prev,
    findings: [...kept, ...result.findings].sort(byPriority),
    sources: { ...prev.sources, [`ci-runner:${new URL(plan.data.url).hostname}`]: { status: "ok", label: plan.data.profile, count: result.findings.length, importedAt: Date.now(), via: "ci" as const } },
  });
  await store.putFindings(repo, next);
  return Response.json({ findings: result.findings.length, accepted: result.accepted, rejected: result.rejected, notes: result.notes }, { headers: NO_STORE });
}
