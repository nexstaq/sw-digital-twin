import { bucketsFromTraces, TracesBody } from "@/lib/connectors/otlp";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";
import { otlpAuthorized, otlpConfigured } from "@/lib/connectors/otlp-config";
import { poke } from "@/lib/github/bus";
import { persist } from "@/lib/persist";

export const maxDuration = 30;

const MAX_BYTES = 4_000_000;

/**
 * OTLP/HTTP JSON traces receiver. Point an OpenTelemetry exporter here:
 *   OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://HOST/api/otlp/v1/traces
 *   OTEL_EXPORTER_OTLP_PROTOCOL=http/json
 *   OTEL_EXPORTER_OTLP_HEADERS=authorization=Bearer <OTLP_INGEST_KEY>,x-twin-repo=owner/name
 * Spans are reduced to 5-minute rollups on arrival and then discarded.
 */
export async function POST(req: Request) {
  const rl = rateLimit(req, LIMITS.otlp);
  if (!rl.ok) return tooMany(rl);
  if (!otlpConfigured()) return Response.json({ error: "Trace ingest is not configured (set OTLP_INGEST_KEY)." }, { status: 503 });
  if (!otlpAuthorized(req.headers.get("authorization"))) return Response.json({ error: "Unauthorized." }, { status: 401 });

  const repo = (req.headers.get("x-twin-repo") ?? "").toLowerCase();
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo) || repo.includes("..")) return Response.json({ error: "Send the repository in an x-twin-repo header (owner/name)." }, { status: 400 });
  if (!(req.headers.get("content-type") ?? "").includes("json")) {
    return Response.json({ error: "Only OTLP/HTTP JSON is supported. Set OTEL_EXPORTER_OTLP_PROTOCOL=http/json." }, { status: 415 });
  }

  const raw = await req.text();
  if (raw.length > MAX_BYTES) return Response.json({ error: "Batch too large." }, { status: 413 });
  let parsed;
  try { parsed = TracesBody.safeParse(JSON.parse(raw)); } catch { parsed = null; }
  if (!parsed?.success) return Response.json({ error: "Not a valid OTLP traces payload." }, { status: 400 });

  const buckets = bucketsFromTraces(parsed.data);
  if (buckets.length) { await persist().putBuckets(repo, buckets); poke(repo); }
  // OTLP success response: an empty partialSuccess means everything was accepted
  return Response.json({ partialSuccess: {} });
}
