import { z } from "zod";
import { techniqueId } from "../../roe";
import { defineTool } from "../tools";

/**
 * A non-intrusive request to a real site, for the gray-box agent. Two things make it safe to hand to a model:
 *  - the URL is checked by `allow()` before this runs (exact verified host, https, standard port, no IP, ownership proved in this run);
 *  - it returns a status and a short allowlist of headers, never a body.
 *
 * The transport is passed in. X9 will give it the S4 networking code (public addresses only, the validated address is the one
 * connected to, no redirects off the host, size and time caps); this file must not grow its own way of making requests.
 */

export interface ProbeResult { status: number; headers: Record<string, string>; bodyBytes: number }
export type ProbeTransport = (url: string, signal: AbortSignal) => Promise<ProbeResult>;

const SHOWN = new Set(["server", "content-type", "strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy", "cache-control"]);

export function probeTool(o: { transport: ProbeTransport }) {
  return defineTool({
    name: "http_probe",
    description: "Make one ordinary GET request to the approved site and report the status and a few security-relevant headers. Never returns the page. You must name the ATT&CK technique.",
    inputSchema: z.strictObject({ url: z.string().min(1).max(2048), technique: techniqueId }),
    classOf: () => "probe",
    techniqueOf: (i) => i.technique,
    targetOf: (i) => ({ kind: "verified-domain" as const, url: i.url }),
    source: "tool-output",
    summarize: (out: ProbeResult) => `status ${out.status}`,
    run: async (i, ctx) => {
      const r = await o.transport(i.url, ctx.signal);
      return { status: r.status, bodyBytes: r.bodyBytes, headers: Object.fromEntries(Object.entries(r.headers).map(([k, v]) => [k.toLowerCase(), v]).filter(([k]) => SHOWN.has(k as string))) };
    },
  });
}
