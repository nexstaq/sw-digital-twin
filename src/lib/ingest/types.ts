import type { Evidence, NodeKind, TwinEdge, TwinGraph } from "@/lib/graph/types";

/** Which top-level area a raw node belongs to. Drives deterministic L0 clustering. */
export type Group = "ci" | "infra" | "service" | "data" | "external";

export interface RawNode {
  id: string;
  kind: NodeKind;
  label: string;
  summary: string;
  /** every claim must cite where it came from */
  evidence: Evidence[];
  group: Group;
  /** hierarchy; a node with no parent is attached to its group cluster (or is itself L0 for services) */
  parent?: string;
  owners?: string[];
  /** churn hotspot etc., 0..1 */
  hotness?: number;
}

export interface RawEdge {
  from: string;
  to: string;
  kind: TwinEdge["kind"];
}

export interface RawGraph {
  nodes: RawNode[];
  edges: RawEdge[];
}

export interface DetectorContext {
  repo: string;
  /** repo-relative, posix-style paths of every file we are willing to read */
  files: string[];
  /** read a repo-relative file as text (null if missing/too large) */
  read(path: string): Promise<string | null>;
  /** repo-relative dir that has git history for churn, or undefined */
  git?: { churn(): Promise<Map<string, number>> };
}

export interface Detector {
  name: string;
  detect(ctx: DetectorContext): Promise<Partial<RawGraph>>;
}

export type IngestEvent =
  | { type: "stage"; stage: string; message: string; pct: number }
  | { type: "graph"; graph: TwinGraph; stats: Stats }
  | { type: "done"; graph: TwinGraph; stats: Stats; ms: number; warnings: string[]; commit?: { sha: string; committedAt: string } }
  | { type: "error"; message: string };

export interface Stats {
  nodes: number;
  edges: number;
  files: number;
}
