import { appOrigin } from "@/lib/auth/origin";
import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { parseRepo } from "@/lib/ingest/repo";
import { persist } from "@/lib/persist";
import { byPriority } from "@/lib/security/map";
import { verifyActionsToken, type ActionsClaims } from "@/lib/security/oidc";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";
import { MAX_SARIF_BYTES, mergeImport, parseSarif } from "@/lib/security/sarif-import";
import { refreshTrend } from "@/lib/security/trend";
import type { FindingSet } from "@/lib/security/types";

const NO_STORE = { "cache-control": "private, no-store" };
const err = (error: string, status: number) => Response.json({ error }, { status, headers: NO_STORE });

/**
 * Import a SARIF report (Semgrep, CodeQL, Trivy, ZAP, Nuclei, gitleaks…) into a repository's findings. Two ways in:
 *  - a signed-in person with PUSH access uploads a file;
 *  - a CI workflow presents its GitHub Actions OIDC token (`Authorization: Bearer …`). The token proves which repository the
 *    workflow belongs to, so a workflow can import only into its own repository, and there is no long-lived secret to leak.
 * The report is untrusted input: size-capped, parsed defensively, secret-shaped text redacted.
 */
export async function POST(req: Request) {
  const rl = rateLimit(req, LIMITS.import);
  if (!rl.ok) return tooMany(rl);
  let repo: string;
  try { const r = parseRepo(new URL(req.url).searchParams.get("repo") ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) {
    return err((e as Error).message, 400);
  }

  const bearer = /^Bearer\s+(\S+)$/i.exec(req.headers.get("authorization") ?? "")?.[1];
  let ci: ActionsClaims | null = null;
  let setCookie: string | undefined;
  if (bearer) {
    const v = await verifyActionsToken(bearer, { audience: appOrigin(req) });
    if (!v.ok) return err(`That CI token was refused (${v.reason}).`, 401);
    if (v.claims.repository.toLowerCase() !== repo) return err("That CI token belongs to a different repository.", 403);
    ci = v.claims;
  } else {
    const a = await authorizeRepo(req, repo, { need: "push" });
    if (!a.ok) return err(a.message, a.status);
    setCookie = a.setCookie;
  }

  if (Number(req.headers.get("content-length") ?? 0) > MAX_SARIF_BYTES) return err("That file is too large (5 MB limit).", 413);
  const text = await req.text();
  if (text.length > MAX_SARIF_BYTES) return err("That file is too large (5 MB limit).", 413);
  let doc: unknown;
  try { doc = JSON.parse(text); } catch { return err("That is not valid JSON.", 400); }

  const parsed = parseSarif(doc);
  if (!parsed.tool) return err(parsed.warnings[0] ?? "That does not look like a SARIF report.", 400);

  const store = persist();
  let prev: FindingSet | null = await store.getFindings(repo);
  if (!prev) {
    // a CI run can arrive before anyone has scanned; it names the commit it ran on, so the import can stand on its own
    if (ci?.sha && /^[0-9a-f]{40}$/.test(ci.sha)) prev = { repo, sha: ci.sha, scannedAt: Date.now(), findings: [], stats: { files: 0, packages: 0, lockfiles: 0 }, warnings: [] };
    else return err("Run a security scan first, then import.", 409);
  }

  const now = Date.now();
  const next = refreshTrend({
    ...prev,
    findings: mergeImport(prev.findings, parsed).sort(byPriority),
    sources: {
      ...prev.sources,
      [`sarif:${parsed.slug}`]: {
        status: "ok", label: parsed.tool, count: parsed.findings.length, importedAt: now, via: ci ? "ci" : "upload",
        ...(parsed.warnings.length ? { message: parsed.warnings.join(" ") } : {}),
        ...(ci ? { by: { ref: ci.ref, workflow: ci.workflow, runId: ci.run_id, actor: ci.actor } } : {}),
      },
    },
  });
  await store.putFindings(repo, next);
  return withSetCookie(Response.json({ tool: parsed.tool, imported: parsed.findings.length, skipped: parsed.skipped, warnings: parsed.warnings }, { headers: NO_STORE }), setCookie);
}

/** Remove one imported report (and the findings it brought) from a repository. Signed-in maintainers only: CI can add, not delete. */
export async function DELETE(req: Request) {
  const rl = rateLimit(req, LIMITS.import);
  if (!rl.ok) return tooMany(rl);
  const url = new URL(req.url);
  let repo: string;
  try { const r = parseRepo(url.searchParams.get("repo") ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) {
    return err((e as Error).message, 400);
  }
  const source = url.searchParams.get("source") ?? "";
  if (!/^sarif:[a-z0-9-]{1,40}$/.test(source)) return err("Only an imported report can be removed.", 400);
  const a = await authorizeRepo(req, repo, { need: "push" });
  if (!a.ok) return err(a.message, a.status);

  const store = persist();
  const prev = await store.getFindings(repo);
  if (!prev?.sources?.[source]) return err("There is no such imported report.", 404);
  const { [source]: _gone, ...rest } = prev.sources; // eslint-disable-line @typescript-eslint/no-unused-vars
  const kept = prev.findings.filter((f) => f.detail.source !== source);
  const next = refreshTrend({ ...prev, findings: kept, ...(Object.keys(rest).length ? { sources: rest } : { sources: undefined }) });
  await store.putFindings(repo, next);
  return withSetCookie(Response.json({ removed: prev.findings.length - kept.length }, { headers: NO_STORE }), a.setCookie);
}
