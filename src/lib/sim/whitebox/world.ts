// Test helper: the real scanner and the real map builder, run over the e2e fixture repository. Not imported by production code.
import path from "node:path";
import { analyzeDirectory as mapDirectory } from "@/lib/ingest/pipeline";
import type { TwinGraph } from "@/lib/graph/types";
import { analyzeDirectory as scanDirectory } from "@/lib/security/scan";
import type { FindingSet } from "@/lib/security/types";

export const FIXTURE_DIR = path.join(process.cwd(), "e2e/fixture");
export const SHA = "f".repeat(40);

let cached: Promise<{ graph: TwinGraph; set: FindingSet }> | undefined;

/** the map and the findings for the fixture, exactly as the app would produce them (no network: the dependency check is off) */
export function fixtureWorld() {
  return (cached ??= (async () => {
    let graph: TwinGraph | undefined;
    for await (const e of mapDirectory(FIXTURE_DIR, "acme/shop", Date.now(), undefined, { narrate: async (g) => ({ graph: g, source: "rules" }) })) if (e.type === "done") graph = e.graph;
    if (!graph) throw new Error("the fixture produced no map");
    const endpointFiles = [...new Set(graph.nodes.filter((n) => n.kind === "endpoint").flatMap((n) => n.evidence.map((x) => x.path)))];
    const set = await scanDirectory(FIXTURE_DIR, "acme/shop", SHA, { fetch: (async () => new Response(JSON.stringify({ results: [] }))) as never }, { endpointFiles });
    return { graph, set };
  })());
}
