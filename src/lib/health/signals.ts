/** Normalised live signals. Connectors (GitHub now, Sentry/Vercel/OTLP later) produce these; the engine only reads these. */

export interface JobSignal {
  name: string;
  status: string;
  conclusion: string | null;
  failedStep?: string;
  url: string;
}

export interface RunSignal {
  id: number;
  /** e.g. ".github/workflows/ci.yml" */
  workflowPath: string;
  workflowName: string;
  branch: string;
  sha: string;
  event: string;
  status: string;
  conclusion: string | null;
  attempt: number;
  createdAt: string;
  /** when it last changed (GitHub `updated_at`); lets replay know whether it had finished at a past time */
  completedAt?: string;
  url: string;
  /** only loaded for the latest completed run of each workflow */
  jobs?: JobSignal[];
}

export type DeployState = "success" | "failure" | "error" | "in_progress" | "queued" | "pending" | "inactive" | "unknown";

export interface DeploySignal {
  id: number;
  environment: string;
  sha: string;
  state: DeployState;
  createdAt: string;
  url: string;
}


/**
 * One minute-rate rollup of runtime telemetry for a service, from any source. We are not a telemetry backend:
 * connectors reduce what they read to these compact buckets (5 minutes each) and nothing finer is stored.
 */
export interface RuntimeBucket {
  /** "sentry" | "otlp" | "vercel" ... */
  source: string;
  /** the service / project name in that tool, e.g. the Sentry project slug or OTLP service.name */
  key: string;
  /** bucket start, epoch ms */
  ts: number;
  /** errors per minute */
  errors?: number;
  /** requests per minute (lets us compute an error rate) */
  requests?: number;
  p95Ms?: number;
  /** links worth showing when this node is unhealthy (e.g. top Sentry issues) */
  top?: { title: string; count: number; url: string }[];
}

export interface SignalSet {
  repo: string;
  defaultBranch: string;
  fetchedAt: number;
  runs: RunSignal[];
  deploys: DeploySignal[];
  runtime?: RuntimeBucket[];
  /** confirmed matches from a tool's service to a graph node: "sentry:payments" -> node id */
  mappings?: Record<string, string>;
}
