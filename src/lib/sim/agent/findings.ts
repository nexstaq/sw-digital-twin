import { z } from "zod";
import type { AuditEntry } from "../audit";
import { techniqueId } from "../roe";
import { sanitizeText } from "./untrusted";

/**
 * What an agent is allowed to report. A finding is a claim, and a claim with nothing behind it is dropped: every finding must
 * cite at least one thing this run actually did (an audit step that produced a result) or one piece of evidence that is really
 * on the map, and everything it names must exist. The model cannot make a finding true by writing it confidently.
 */

export const CitationSchema = z.union([
  z.strictObject({ step: z.number().int().nonnegative() }),
  z.strictObject({ ref: z.string().min(1).max(300) }),
]);

export const AgentFindingSchema = z.strictObject({
  title: z.string().min(3).max(120),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  summary: z.string().min(3).max(500),
  technique: techniqueId.optional(),
  nodeIds: z.array(z.string().max(300)).max(10).default([]),
  citations: z.array(CitationSchema).max(10),
});
export const FindingsOutputSchema = z.strictObject({ findings: z.array(AgentFindingSchema).max(20) });

export type AgentFinding = z.infer<typeof AgentFindingSchema>;
export interface ValidatedFinding extends Omit<AgentFinding, "citations"> { citations: z.infer<typeof CitationSchema>[] }
export interface DroppedFinding { title: string; why: string }

export interface FindingContext {
  audit: readonly AuditEntry[];
  /** evidence refs that are really on the map ("path:lines"); omit to disallow `ref` citations */
  knownRefs?: ReadonlySet<string>;
  /** block ids that are really on the map; omit to skip the check */
  knownNodeIds?: ReadonlySet<string>;
  allowedTechniques: readonly string[];
}

const URL_RE = /\b(?:https?:\/\/|www\.)\S+/gi;
const TAG_RE = /<\/?[a-z][^>]*>/gi;
const text = (s: string, n: number) => sanitizeText(s.replace(URL_RE, "").replace(TAG_RE, "").replace(/[`*_#>]/g, ""), n).text;

export function validateFindings(raw: unknown, ctx: FindingContext): { kept: ValidatedFinding[]; dropped: DroppedFinding[] } {
  const parsed = FindingsOutputSchema.safeParse(raw);
  if (!parsed.success) return { kept: [], dropped: [{ title: "(the whole answer)", why: "It was not in the required format, so none of it was used." }] };

  const results = new Map<number, AuditEntry>();
  for (const e of ctx.audit) if (e.kind === "tool-result") results.set(e.seq, e);

  const kept: ValidatedFinding[] = [];
  const dropped: DroppedFinding[] = [];
  for (const f of parsed.data.findings) {
    const why = (() => {
      if (f.citations.length === 0) return "It cites nothing: no step of this run and no evidence on the map.";
      for (const c of f.citations) {
        if ("step" in c && !results.has(c.step)) return `It cites step ${c.step}, which is not a result produced in this run.`;
        if ("ref" in c && !ctx.knownRefs?.has(c.ref)) return `It cites evidence (${text(c.ref, 80)}) that is not on the map.`;
      }
      if (ctx.knownNodeIds) for (const id of f.nodeIds) if (!ctx.knownNodeIds.has(id)) return "It names a block that is not on the map.";
      if (f.technique && !ctx.allowedTechniques.includes(f.technique)) return `It names technique ${f.technique}, which this run was not allowed to use.`;
      return null;
    })();
    if (why) { dropped.push({ title: text(f.title, 120) || "(untitled)", why }); continue; }
    const title = text(f.title, 120), summary = text(f.summary, 500);
    if (!title || !summary) { dropped.push({ title: title || "(untitled)", why: "Nothing was left of it after removing links, markup and instruction-like text." }); continue; }
    kept.push({ ...f, title, summary });
  }
  return { kept, dropped };
}
