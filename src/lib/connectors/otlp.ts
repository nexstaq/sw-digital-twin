import { z } from "zod";
import type { RuntimeBucket } from "@/lib/health/signals";
import { BUCKET_MS } from "@/lib/persist/types";

/**
 * OTLP/HTTP **JSON** traces -> 5-minute rollups per service.name. Spans are reduced on arrival and discarded:
 * what is kept is errors/min, requests/min and p95 latency, nothing else. Protobuf is not accepted (set
 * OTEL_EXPORTER_OTLP_PROTOCOL=http/json).
 */
const Attr = z.object({ key: z.string(), value: z.object({ stringValue: z.string().optional() }).passthrough() });
const Span = z.object({
  startTimeUnixNano: z.union([z.string(), z.number()]), endTimeUnixNano: z.union([z.string(), z.number()]),
  kind: z.number().optional(), status: z.object({ code: z.number().optional() }).optional(), parentSpanId: z.string().optional(),
});
export const TracesBody = z.object({
  resourceSpans: z.array(z.object({
    resource: z.object({ attributes: z.array(Attr).optional() }).optional(),
    scopeSpans: z.array(z.object({ spans: z.array(Span).optional() })).optional(),
  })),
});

/** unix nanoseconds (a string, since they overflow doubles) -> ms */
const nanosToMs = (n: string | number) => (typeof n === "number" ? Math.trunc(n / 1e6) : Number(n.length > 6 ? n.slice(0, -6) : "0"));
const SERVER = 2;

export function bucketsFromTraces(body: z.infer<typeof TracesBody>): RuntimeBucket[] {
  const acc = new Map<string, { key: string; ts: number; requests: number; errors: number; dur: number[] }>();
  for (const rs of body.resourceSpans) {
    const key = rs.resource?.attributes?.find((a) => a.key === "service.name")?.value.stringValue;
    if (!key) continue;
    for (const ss of rs.scopeSpans ?? []) for (const sp of ss.spans ?? []) {
      // count entry points, not every internal call: server spans, or root spans from SDKs that leave kind unset
      const entry = sp.kind === SERVER || ((sp.kind === undefined || sp.kind === 0) && !sp.parentSpanId);
      if (!entry) continue;
      const start = nanosToMs(sp.startTimeUnixNano);
      const end = nanosToMs(sp.endTimeUnixNano);
      if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) continue;
      const ts = Math.floor(start / BUCKET_MS) * BUCKET_MS;
      const k = `${key}\u0000${ts}`;
      const cur = acc.get(k) ?? acc.set(k, { key, ts, requests: 0, errors: 0, dur: [] }).get(k)!;
      cur.requests++;
      if (sp.status?.code === 2) cur.errors++;
      cur.dur.push(end - start);
    }
  }
  const mins = BUCKET_MS / 60_000;
  return [...acc.values()].map((a) => {
    const d = a.dur.sort((x, y) => x - y);
    return { source: "otlp", key: a.key, ts: a.ts, requests: a.requests / mins, errors: a.errors / mins, p95Ms: d[Math.min(d.length - 1, Math.floor(d.length * 0.95))] };
  });
}
