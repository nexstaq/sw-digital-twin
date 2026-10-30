import type { DeploySignal, RuntimeBucket } from "@/lib/health/signals";

/** One thing in a connected tool that could map to a node: a Sentry project, an OTLP service.name, a Vercel project. */
export interface Target { source: string; key: string; name: string; url?: string }

export interface ConnectorCtx { env: NodeJS.ProcessEnv; fetch: typeof fetch; now: number }

/**
 * A source of live signals. Connectors read from the customer's tools and reduce what they read to compact signals;
 * we are not a telemetry backend. Pull connectors implement `discover` + `poll`. Push sources (OTLP) arrive through
 * their own route and are read back from persistence.
 */
export interface Connector {
  id: string;
  label: string;
  /** env vars that must be set for this connector to run */
  needs: string[];
  configured(env: NodeJS.ProcessEnv): boolean;
  discover(ctx: ConnectorCtx): Promise<Target[]>;
  poll(ctx: ConnectorCtx): Promise<{ buckets?: RuntimeBucket[]; deploys?: DeploySignal[] }>;
}

export type ConnectorState = "off" | "ok" | "error";
export interface ConnectorStatus { id: string; label: string; state: ConnectorState; message?: string; needs: string[] }
