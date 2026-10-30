import type { TwinNode } from "./types";

type Lens = "overview" | "flow" | "ops" | "risk" | "tour";

/** Leaders and tour-takers get friendly names; engineers keep exact identifiers. */
export function displayName(n: TwinNode, lens: Lens): string {
  return (lens === "overview" || lens === "tour") && n.narrative ? n.narrative.name : n.label;
}

/** The description matching the reader of this lens, falling back to the analysis summary. */
export function describeFor(n: TwinNode, lens: Lens): string {
  const nar = n.narrative;
  if (!nar) return n.summary;
  if (lens === "overview" || lens === "tour") return nar.exec;
  if (lens === "risk") return nar.security;
  return nar.engineer;
}
