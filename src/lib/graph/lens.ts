import type { Lens } from "@/lib/store";
import type { TwinNode } from "./types";

/**
 * Lenses are emphasis, not different data. Each decides which tiles at the current level step back.
 *  - overview: nothing dims; friendly names and plain-English lines.
 *  - flow: the delivery path (jobs, environments, packages) stays bright.
 *  - ops: anything healthy steps back so what needs attention stands out (unless everything is healthy).
 *  - risk: the exposure surface (endpoints, external services, data stores) stays bright.
 *  - tour: the tour player decides.
 */
export function dimmedIds(nodes: TwinNode[], lens: Lens): Set<string> {
  const dim = new Set<string>();
  if (lens === "ops") {
    const attention = nodes.some((n) => n.state === "failing" || n.state === "degraded");
    if (attention) for (const n of nodes) if (n.state === "nominal") dim.add(n.id);
  } else if (lens === "flow") {
    const keep = new Set(["job", "env", "package", "service"]);
    if (nodes.some((n) => keep.has(n.kind))) for (const n of nodes) if (!keep.has(n.kind)) dim.add(n.id);
  } else if (lens === "risk") {
    const keep = new Set(["external", "datastore", "endpoint", "queue"]);
    if (nodes.some((n) => keep.has(n.kind))) for (const n of nodes) if (!keep.has(n.kind)) dim.add(n.id);
  }
  return dim;
}

/** The line under a tile's name, written for the reader of the lens. */
export function tileSubtitle(n: TwinNode, lens: Lens): string | undefined {
  if (lens === "overview") return n.narrative?.exec ?? n.summary;
  if (lens === "ops") return n.reasons[0] ?? (n.live ? "Running now" : undefined);
  if (lens === "risk") return n.narrative?.security;
  return undefined; // flow: kind and structure speak for themselves
}
