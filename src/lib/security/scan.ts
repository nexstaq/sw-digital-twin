import { listFiles, makeReader } from "@/lib/ingest/repo";
import { analyzeCode } from "./analyzers/code";
import { analyzeContainers } from "./analyzers/container";
import { analyzeExposure } from "./analyzers/exposure";
import { analyzeDependencies } from "./analyzers/dependencies";
import type { OsvOpts } from "./analyzers/osv";
import { analyzePipelines } from "./analyzers/pipeline";
import { analyzeSecrets } from "./analyzers/secrets";
import { byPriority } from "./map";
import type { FindingSet, SecurityContext } from "./types";

/**
 * Runs every analyzer over one checkout. An analyzer that throws costs you ITS findings and adds a warning: it can never
 * turn into a silent all-clear, and it never takes the other analyzers down with it.
 */
export async function analyzeContext(ctx: SecurityContext, meta: { sha: string; now?: number }, o: OsvOpts = {}, extra: { endpointFiles?: string[] } = {}): Promise<FindingSet> {
  const warnings: string[] = [];
  const guard = async <T>(name: string, run: () => Promise<T>, fallback: T): Promise<T> => {
    try { return await run(); } catch (e) { warnings.push(`${name} check failed (${e instanceof Error ? e.message : "unknown error"}), so its results are missing.`); return fallback; }
  };
  const [deps, secrets, pipelines, containers, code] = await Promise.all([
    guard("Dependency", () => analyzeDependencies(ctx, o), { findings: [], packages: 0, lockfiles: 0, warnings: [] }),
    guard("Secrets", () => analyzeSecrets(ctx), []),
    guard("Pipeline", () => analyzePipelines(ctx), []),
    guard("Container", () => analyzeContainers(ctx), []),
    guard("Code", () => analyzeCode(ctx), []),
  ]);
  const exposure = extra.endpointFiles?.length ? await guard("Exposure", () => analyzeExposure(ctx, extra.endpointFiles!), null) : null;
  warnings.push(...deps.warnings);
  const findings = [...deps.findings, ...secrets, ...pipelines, ...containers, ...code, ...(exposure?.findings ?? [])].sort(byPriority);
  return { repo: ctx.repo, sha: meta.sha, scannedAt: meta.now ?? Date.now(), findings, stats: { files: ctx.files.length, packages: deps.packages, lockfiles: deps.lockfiles }, ...(exposure ? { exposure: exposure.exposure } : {}), warnings };
}

/** Same, over a checked-out directory. */
export async function analyzeDirectory(dir: string, repo: string, sha: string, o: OsvOpts = {}, extra: { endpointFiles?: string[] } = {}): Promise<FindingSet> {
  return analyzeContext({ repo, files: await listFiles(dir), read: makeReader(dir) }, { sha }, o, extra);
}
