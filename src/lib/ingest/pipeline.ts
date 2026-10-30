import { validateGraph } from "@/lib/graph/integrity";
import { actionsDetector } from "./detectors/actions";
import { codeDetector } from "./detectors/code";
import { infraDetector } from "./detectors/infra";
import { packagesDetector } from "./detectors/packages";
import { buildGraph, enrich, mergeRaw } from "./builder";
import { fileCache } from "@/lib/narrate/cache";
import { narrate, type NarrateResult } from "@/lib/narrate/narrate";
import type { TwinGraph } from "@/lib/graph/types";
import { cloneRepo, gitChurn, gitHead, listFiles, makeReader, parseRepo } from "./repo";
import type { Detector, DetectorContext, IngestEvent, RawGraph } from "./types";

const DETECTORS: Detector[] = [actionsDetector, packagesDetector, infraDetector, codeDetector];
const DETECTOR_TIMEOUT_MS = 30_000;

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let t: ReturnType<typeof setTimeout>;
  return Promise.race([
    p,
    new Promise<never>((_, rej) => { t = setTimeout(() => rej(new Error(`${what} timed out`)), ms); }),
  ]).finally(() => clearTimeout(t));
}

export interface IngestInput {
  repo: string;
  ref?: string;
  /** read token for a private repo (already authorised by the caller) */
  token?: string;
  /** private repos never go to a free-tier model */
  private?: boolean;
}

/**
 * repo URL -> streaming events -> canonical graph.
 * Each detector is isolated: a crash or timeout becomes a warning and the scan keeps its partial map.
 */
export async function* runIngest(input: IngestInput, signal?: AbortSignal): AsyncGenerator<IngestEvent> {
  const started = Date.now();
  let checkout: Awaited<ReturnType<typeof cloneRepo>> | undefined;
  try {
    const repo = parseRepo(input.repo, input.ref);
    yield { type: "stage", stage: "clone", message: `Cloning ${repo.owner}/${repo.name}…`, pct: 5 };
    checkout = await cloneRepo(repo, signal, input.token);
    const commit = checkout.head ?? await gitHead(checkout.dir);
    for await (const ev of analyzeDirectory(checkout.dir, `${repo.owner}/${repo.name}`, started, signal, { private: input.private })) yield ev.type === "done" ? { ...ev, commit } : ev;
  } catch (e) {
    yield { type: "error", message: e instanceof Error ? e.message : "Scan failed" };
  } finally {
    await checkout?.cleanup();
  }
}

export interface AnalyzeOptions {
  /** replaces the plain-English step (tests, or callers that want deterministic output only) */
  narrate?: (graph: TwinGraph, readme?: string) => Promise<NarrateResult>;
  /** private repo: descriptions may only use a provider with a no-training guarantee (the gateway), never a free dev key */
  private?: boolean;
}

/** Everything after the clone. Separate so it can be tested against a local directory. */
export async function* analyzeDirectory(
  dir: string, label: string, started = Date.now(), signal?: AbortSignal, opts: AnalyzeOptions = {},
): AsyncGenerator<IngestEvent> {
  yield { type: "stage", stage: "scan", message: "Reading the file tree…", pct: 20 };
  const files = await listFiles(dir);
  const read = makeReader(dir);
  let churn: Map<string, number> | undefined;
  const ctx: DetectorContext = {
    repo: label, files, read,
    git: { churn: async () => (churn ??= await gitChurn(dir)) },
  };
  const warnings: string[] = [];
  const parts: Partial<RawGraph>[] = [];
  const stats = (g: { nodes: unknown[]; edges: unknown[] }) => ({ nodes: g.nodes.length, edges: g.edges.length, files: files.length });

  for (const [i, d] of DETECTORS.entries()) {
    if (signal?.aborted) { yield { type: "error", message: "Scan cancelled" }; return; }
    yield { type: "stage", stage: d.name, message: `Analysing ${d.name.toLowerCase()}…`, pct: 25 + Math.round((i / DETECTORS.length) * 55) };
    try {
      parts.push(await withTimeout(d.detect(ctx), DETECTOR_TIMEOUT_MS, d.name));
    } catch (e) {
      warnings.push(`${d.name}: ${e instanceof Error ? e.message : "failed"}`);
    }
    // stream the map as it grows so the UI can build it live
    const partial = buildGraph(mergeRaw(parts), label);
    yield { type: "graph", graph: partial, stats: stats(partial) };
  }

  yield { type: "stage", stage: "finish", message: "Adding owners and change hotspots…", pct: 88 };
  const merged = mergeRaw(parts);
  const co = (await read("CODEOWNERS")) ?? (await read(".github/CODEOWNERS")) ?? (await read("docs/CODEOWNERS"));
  enrich(merged.nodes, { codeowners: co, churn: await ctx.git!.churn() });

  let graph = buildGraph(merged, label);
  if (graph.nodes.length === 0) warnings.push("No workflows, services or infrastructure were recognised in this repository.");
  const problems = validateGraph(graph);
  if (problems.length) {
    warnings.push(`Graph integrity: ${problems.length} issue(s), e.g. ${problems[0]}`);
    const ids = new Set(graph.nodes.map((n) => n.id));
    graph = { ...graph, edges: graph.edges.filter((e) => ids.has(e.from) && ids.has(e.to)) };
  }

  if (graph.nodes.length > 0) {
    yield { type: "stage", stage: "narrate", message: "Writing the plain-English layer…", pct: 93 };
    // README text is opt-in: by default only metadata derived from analysis reaches the model
    const readme = process.env.NARRATE_INCLUDE_README === "1" ? (await read("README.md")) ?? undefined : undefined;
    const run = opts.narrate ?? ((g, r) => narrate(g, { cache: fileCache(), readme: r, signal, private: opts.private }));
    const result = await run(graph, readme);
    graph = result.graph;
    if (result.warning) warnings.push(result.warning);
    yield { type: "graph", graph, stats: stats(graph) };
  }
  yield { type: "done", graph, stats: stats(graph), ms: Date.now() - started, warnings };
}
