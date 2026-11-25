import type { NodeKind } from "@/lib/graph/types";
import type { Severity } from "@/lib/security/types";

/**
 * The range: a virtual, deterministic copy of the software's own blocks, built from the map and the scanner's findings.
 * Nothing in it is real. It has no sockets, no files, no clock and no randomness of its own (see runtime.ts), so nothing can
 * leave it and the same snapshot always behaves the same way.
 *
 * Attacks are not strings. An agent sends a payload CLASS ("sqli", "ssrf"), never exploit text, and the range answers from
 * the weaknesses the scanner already found. A proof is a harmless marker, never working exploit code.
 */

export const PAYLOAD_CLASSES = ["sqli", "cmdi", "code-injection", "path-traversal", "ssrf", "xss", "open-redirect"] as const;
export type PayloadClass = (typeof PAYLOAD_CLASSES)[number];

export const ROLES = ["anonymous", "user", "admin"] as const;
export type Role = (typeof ROLES)[number];

export const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "PAGE", "ALL"] as const;
export type Method = (typeof METHODS)[number];
export const WRITE_METHODS: ReadonlySet<string> = new Set(["POST", "PUT", "PATCH", "DELETE", "ALL"]);

export type WeaknessKind =
  | "sql-injection" | "command-injection" | "code-injection" | "path-traversal" | "ssrf" | "xss" | "open-redirect"
  | "no-auth"
  | "exposed-credential" | "vulnerable-dependency" | "container-misconfig"
  | "pipeline-injection" | "pipeline-misconfig";

/**
 * One thing the scanner found, as the range models it. `reachable` means something in the range can currently exercise it:
 * an endpoint that takes the payload class, a write route with no auth check, or a workflow an outsider can trigger.
 * The rest are recorded as latent (they exist, but nothing here reaches them yet) and are material for the red team (X6).
 * Carries no path, line, source or secret: look the finding up by `findingId`.
 */
export interface Weakness {
  id: string;
  kind: WeaknessKind;
  findingId: string;
  ruleId: string;
  severity: Severity;
  /** the map node that owns it */
  nodeId: string;
  /** endpoints that can exercise it (web weaknesses) */
  endpointIds: string[];
  payload?: PayloadClass;
  /** the harmless marker a successful exercise returns */
  proof: string;
  reachable: boolean;
}

export interface EmulatorSpec {
  nodeId: string;
  kind: NodeKind;
  label: string;
  parentId?: string;
  /** virtual milliseconds one visit takes, before jitter */
  latencyMs: number;
  jitterMs: number;
  /** jobs and workflows: virtual duration of a run */
  durationMs?: number;
}

export interface EndpointSpec {
  nodeId: string;
  /** the service whose dependencies this route walks */
  ownerId: string;
  method: Method;
  path: string;
  segments: string[];
  /** "none": accepts anonymous calls on a write route. "required": needs a signed-in role. "public-read": read-only, open */
  auth: "none" | "required" | "public-read";
  /** "finding" when the scanner said so; "assumed" when this is only the range's default */
  authSource: "finding" | "assumed";
}

export interface DatastoreSpec {
  nodeId: string;
  /** synthetic tables only: no real names or data ever */
  tables: { name: string; rows: number }[];
  /** reaching this datastore through an exercised weakness proves impact */
  crown: string;
}

export interface RangeEdge { id: string; from: string; to: string; kind: string }

export interface RangeSpec {
  version: 1;
  /** usable as a `range` target id in the rules of engagement */
  id: string;
  specHash: string;
  repo: string;
  sha: string;
  seed: number;
  emulators: EmulatorSpec[];
  endpoints: EndpointSpec[];
  datastores: DatastoreSpec[];
  edges: RangeEdge[];
  weaknesses: Weakness[];
  /** everything that was left out or could not be modelled, so the range never looks more complete than it is */
  notes: string[];
}

export interface RangeRequest {
  method: Method;
  path: string;
  role: Role;
  payload?: { class: PayloadClass };
}

export interface RangeResponse {
  status: number;
  traceId: string;
  ms: number;
  body: string;
  /** a weakness was exercised: the marker, and what the request reached */
  proof?: string;
  reached?: string[];
  /** crown markers of datastores reached by an exercised weakness */
  crown?: string[];
}

export type EventKind = "request" | "visit" | "job" | "deploy";
export interface RangeEvent {
  seq: number;
  /** virtual milliseconds since the range started */
  t: number;
  traceId: string;
  kind: EventKind;
  nodeId: string;
  from?: string;
  via?: string;
  ok: boolean;
  ms: number;
  status?: number;
  note?: string;
}

export type Fault = { kind: "latency"; ms: number } | { kind: "error"; rate: number } | { kind: "outage" };

export interface FlowResult {
  ok: boolean;
  traceId: string;
  ms: number;
  visited: string[];
  /** datastores, external services, queues and environments that were reached and answered */
  reached: string[];
  failedAt?: string;
}

export interface WorkflowResult {
  runId: number;
  workflowId: string;
  sha: string;
  trigger: "push" | "pull_request" | "outsider-pr";
  conclusion: "success" | "failure";
  startedAt: number;
  endedAt: number;
  jobs: { nodeId: string; label: string; /** a job, or an environment that is a deploy step inside the workflow */ stage: "job" | "env"; conclusion: "success" | "failure" | "skipped"; startedAt: number; endedAt: number; failedStep?: string }[];
  deploys: { envId: string; state: "success" | "failure"; sha: string }[];
  proofs: string[];
}
