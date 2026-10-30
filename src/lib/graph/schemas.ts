import { z } from "zod";

export const SCHEMA_VERSION = 1 as const;

export const StatusSchema = z.enum(["nominal", "degraded", "failing", "unknown"]);

export const NodeKindSchema = z.enum([
  "service", "job", "package", "datastore", "queue", "external", "endpoint", "file", "env",
]);

export const EvidenceSchema = z.object({
  path: z.string().min(1),
  lines: z.string().optional(),
  runId: z.string().optional(),
});

/** Plain-English layer written for a node. Everything in it must be backed by `citations` (evidence refs). */
export const NarrativeSchema = z.object({
  name: z.string(),
  purpose: z.string(),
  exec: z.string(),
  engineer: z.string(),
  security: z.string(),
  confidence: z.enum(["high", "medium", "low"]),
  /** "path:lines" strings that exist in the graph's evidence */
  citations: z.array(z.string()),
  /** left-to-right position among siblings, from the flow hint */
  order: z.number().optional(),
});

export const NodeSchema = z.object({
  id: z.string().min(1),
  level: z.union([z.literal(0), z.literal(1), z.literal(2)]),
  parentId: z.string().optional(),
  kind: NodeKindSchema,
  label: z.string().min(1),
  summary: z.string(),
  state: StatusSchema,
  /** 0..1, higher is healthier */
  score: z.number().min(0).max(1),
  /** recent error/health trend, 0..1, higher is worse */
  spark: z.array(z.number().min(0).max(1)),
  reasons: z.array(z.string()),
  evidence: z.array(EvidenceSchema),
  owners: z.array(z.string()).optional(),
  /** 1 = low, 2 = normal, 3 = critical. Controls how much a failure propagates up. */
  criticality: z.union([z.literal(1), z.literal(2), z.literal(3)]).default(2),
  narrative: NarrativeSchema.optional(),
  /** Links to the runs / deployments behind `reasons` (live health only) */
  links: z.array(z.object({ label: z.string(), url: z.string(), ok: z.boolean().optional() })).optional(),
  /** A run or deploy for this node is in flight right now */
  live: z.boolean().optional(),
});

export const EdgeKindSchema = z.enum(["calls", "triggers", "deploys_to", "depends_on", "publishes", "reads"]);

export const EdgeSchema = z.object({
  id: z.string().min(1),
  from: z.string().min(1),
  to: z.string().min(1),
  kind: EdgeKindSchema,
  /** 0..1 relative traffic, drives particle speed/count */
  throughput: z.number().min(0).max(1),
  /** 0..1, > 0.05 renders as an error edge */
  errorRate: z.number().min(0).max(1),
});

export const DeployMarkerSchema = z.object({
  hoursAgo: z.number().min(0),
  label: z.string(),
  ok: z.boolean(),
});

export const TourStepSchema = z.object({
  nodeId: z.string(),
  title: z.string(),
  caption: z.string(),
});

export const StorySchema = z.object({
  headline: z.string(),
  /** "ai": written by a model and validated; "rules": generated deterministically */
  source: z.enum(["ai", "rules"]),
  model: z.string().optional(),
  tour: z.array(TourStepSchema),
});

/** What is in flight right now (running/queued workflow runs and deployments on the default branch). */
export const ActivitySchema = z.object({
  running: z.number().int().min(0),
  queued: z.number().int().min(0),
  /** ISO time the oldest running item started, for an elapsed timer */
  since: z.string().optional(),
});

export const GraphSchema = z.object({
  repo: z.string(),
  activity: ActivitySchema.optional(),
  story: StorySchema.optional(),
  nodes: z.array(NodeSchema),
  edges: z.array(EdgeSchema),
  deploys: z.array(DeployMarkerSchema),
});

/** One point-in-time health reading for a node. */
export const HealthSchema = z.object({
  nodeId: z.string(),
  ts: z.number(),
  state: StatusSchema,
  score: z.number().min(0).max(1),
  signals: z.array(z.object({ name: z.string(), value: z.number(), threshold: z.number().optional() })),
  reasons: z.array(z.string()),
});

export const SnapshotSchema = z.object({
  schemaVersion: z.literal(SCHEMA_VERSION),
  repoId: z.string(),
  commitSha: z.string(),
  createdAt: z.number(),
  graph: GraphSchema,
});

export type Activity = z.infer<typeof ActivitySchema>;
export type Narrative = z.infer<typeof NarrativeSchema>;
export type TourStep = z.infer<typeof TourStepSchema>;
export type Story = z.infer<typeof StorySchema>;
export type Status = z.infer<typeof StatusSchema>;
export type NodeKind = z.infer<typeof NodeKindSchema>;
export type Evidence = z.infer<typeof EvidenceSchema>;
export type TwinNode = z.infer<typeof NodeSchema>;
export type TwinEdge = z.infer<typeof EdgeSchema>;
export type DeployMarker = z.infer<typeof DeployMarkerSchema>;
export type TwinGraph = z.infer<typeof GraphSchema>;
export type Health = z.infer<typeof HealthSchema>;
export type Snapshot = z.infer<typeof SnapshotSchema>;
