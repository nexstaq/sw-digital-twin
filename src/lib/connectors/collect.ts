import type { DeploySignal, RuntimeBucket } from "@/lib/health/signals";
import { persist } from "@/lib/persist";
import type { Persist } from "@/lib/persist/types";
import { otlpConfigured } from "./otlp-config";
import { sentry } from "./sentry";
import type { Connector, ConnectorCtx, ConnectorStatus, Target } from "./types";
import { vercel } from "./vercel";

export const CONNECTORS: Connector[] = [sentry, vercel];
const HISTORY_MS = 48 * 3_600_000;
const TTL = 60_000;

/**
 * Connector tokens belong to the operator's own accounts. Until sign-in and per-team connections exist, they are served
 * ONLY for repos the operator lists in CONNECTOR_REPOS, so a stranger pasting a public repo cannot read private telemetry.
 */
export const connectorsEnabledFor = (repo: string, env: NodeJS.ProcessEnv = process.env) =>
  (env.CONNECTOR_REPOS ?? "").toLowerCase().split(",").map((s) => s.trim()).filter(Boolean).includes(repo.toLowerCase());

export interface Collected { runtime: RuntimeBucket[]; deploys: DeploySignal[]; targets: Target[]; status: ConnectorStatus[] }

/** Only what we PULL from other tools is cached; pushed telemetry is read from our own storage every time so it is never stale. */
const pulledCache = new Map<string, { at: number; value: Collected }>();

export async function collect(repo: string, o: { env?: NodeJS.ProcessEnv; fetch?: typeof fetch; now?: number; store?: Persist; force?: boolean } = {}): Promise<Collected> {
  const env = o.env ?? process.env;
  const now = o.now ?? Date.now();
  const key = repo.toLowerCase();

  if (!connectorsEnabledFor(repo, env)) {
    const off = (id: string, label: string, needs: string[]) => ({ id, label, state: "off" as const, needs, message: "Not enabled for this repository (see CONNECTOR_REPOS)." });
    return { runtime: [], deploys: [], targets: [], status: [...CONNECTORS.map((c) => off(c.id, c.label, c.needs)), off("otlp", "OpenTelemetry", ["OTLP_INGEST_KEY"])] };
  }

  const hit = pulledCache.get(key);
  let pulled: Collected;
  if (!o.force && !o.store && hit && now - hit.at < TTL) pulled = hit.value;
  else {
    pulled = { runtime: [], deploys: [], targets: [], status: [] };
    const ctx: ConnectorCtx = { env, fetch: o.fetch ?? fetch, now };
    await Promise.all(CONNECTORS.map(async (c) => {
      const base = { id: c.id, label: c.label, needs: c.needs };
      if (!c.configured(env)) return void pulled.status.push({ ...base, state: "off", message: `Set ${c.needs.join(" and ")}.` });
      try {
        const [targets, polled] = await Promise.all([c.discover(ctx), c.poll(ctx)]);
        pulled.targets.push(...targets);
        pulled.runtime.push(...(polled.buckets ?? []));
        pulled.deploys.push(...(polled.deploys ?? []));
        pulled.status.push({ ...base, state: "ok" });
      } catch (e) {
        pulled.status.push({ ...base, state: "error", message: e instanceof Error ? e.message : "Failed." });
      }
    }));
    if (!o.store) pulledCache.set(key, { at: now, value: pulled });
  }

  // pushed telemetry (OTLP) comes back out of storage, fresh every time
  const pushed = (await (o.store ?? persist()).getBuckets(repo, now - HISTORY_MS)).filter((b) => b.source === "otlp");
  const out: Collected = { runtime: [...pulled.runtime, ...pushed], deploys: pulled.deploys, targets: [...pulled.targets], status: [...pulled.status] };
  for (const k of new Set(pushed.map((b) => b.key))) out.targets.push({ source: "otlp", key: k, name: k });
  out.status.push({ id: "otlp", label: "OpenTelemetry", needs: ["OTLP_INGEST_KEY"], state: otlpConfigured(env) ? "ok" : "off", message: otlpConfigured(env) ? (pushed.length ? undefined : "Waiting for the first traces.") : "Set OTLP_INGEST_KEY to accept traces." });
  out.status.sort((a, b) => a.id.localeCompare(b.id));
  return out;
}
