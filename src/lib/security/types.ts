import { z } from "zod";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const SeveritySchema = z.enum(SEVERITIES);
export type Severity = z.infer<typeof SeveritySchema>;

export const CATEGORIES = ["dependency", "secret", "pipeline", "container", "code", "runtime"] as const;
export const CategorySchema = z.enum(CATEGORIES);
export type Category = z.infer<typeof CategorySchema>;

const Vuln = z.object({
  id: z.string(), aliases: z.array(z.string()).default([]), summary: z.string(), severity: SeveritySchema,
  /** CVSS base score when the advisory carries a v3 vector */
  score: z.number().optional(), fixedIn: z.array(z.string()).default([]), url: z.string().optional(),
});
export type Vuln = z.infer<typeof Vuln>;

/**
 * One thing worth fixing, pinned to where it lives. Never carries source code or a secret's value: only where it is, what it
 * is, why it matters and what to do. The code excerpt is fetched from GitHub when someone opens the finding.
 */
export const FindingSchema = z.object({
  /** stable across line shifts, so "new" vs "already known" can be told apart between scans */
  id: z.string(),
  ruleId: z.string(),
  category: CategorySchema,
  severity: SeveritySchema,
  title: z.string(),
  path: z.string(),
  line: z.number().int().positive().optional(),
  endLine: z.number().int().positive().optional(),
  /** plain English: why this is a problem here */
  reason: z.string(),
  fix: z.string(),
  cwe: z.array(z.string()).default([]),
  owasp: z.string().optional(),
  /** how sure we are this is real (a placeholder-looking secret in a test file is "low") */
  confidence: z.enum(["high", "medium", "low"]),
  detail: z.object({
    package: z.string().optional(), ecosystem: z.string().optional(), version: z.string().optional(),
    /** reached from your own manifest, or only pulled in by something else */
    direct: z.boolean().optional(), dev: z.boolean().optional(),
    /** transitive packages: the direct dependency and each package between it and this one ("why do I have this?") */
    via: z.array(z.string()).optional(),
    /** source files that import it (the "is it actually used" signal) */
    usedIn: z.array(z.string()).optional(),
    vulns: z.array(Vuln).optional(),
    /** secrets: which kind, and a masked hint. Never the value. */
    secretKind: z.string().optional(), masked: z.string().optional(),
    /** who reported it when it did not come from our own analyzers: "dependabot", "codeql", "secret-scanning", "sarif:nuclei"… */
    source: z.string().optional(),
    /** the tool's own display name for an imported report ("Nuclei", not "nuclei") */
    sourceName: z.string().optional(),
    /** other tools that independently reported the same thing (so it is one finding, with more evidence) */
    alsoReportedBy: z.array(z.string()).optional(),
    /** a link to where the reporting tool shows it (https only) */
    url: z.string().optional(),
    /** other lines that share this finding (e.g. the same unpinned action used 3 times) */
    lines: z.array(z.number()).optional(),
  }).default({}),
});
export type Finding = z.infer<typeof FindingSchema>;

export const FindingSetSchema = z.object({
  repo: z.string(),
  sha: z.string(),
  scannedAt: z.number(),
  findings: z.array(FindingSchema),
  stats: z.object({ files: z.number(), packages: z.number(), lockfiles: z.number() }),
  /** how exposed the entry points are, for attack paths. Present when a map existed to find endpoints in. */
  exposure: z.object({
    endpointFiles: z.number(),
    /** endpoint files that accept writes and show no authentication check (and no project-wide auth middleware) */
    unauthenticatedWrites: z.array(z.string()),
    middlewareAuth: z.boolean(),
  }).optional(),
  /** safety score and severity counts per scan, oldest first (the last 30) */
  trend: z.array(z.object({ sha: z.string(), scannedAt: z.number(), score: z.number(), total: z.number(), counts: z.record(z.string(), z.number()) })).optional(),
  /** what changed since the scan before this one, judged by stable finding id */
  delta: z.object({ newIds: z.array(z.string()), fixed: z.number(), previousSha: z.string(), previousScannedAt: z.number() }).optional(),
  /** where findings came from besides our own analyzers, and whether each source worked. Never an all-clear by omission. */
  sources: z.record(z.string(), z.object({
    status: z.enum(["ok", "unavailable"]),
    /** display name, for imported reports */
    label: z.string().optional(),
    count: z.number(),
    message: z.string().optional(),
    importedAt: z.number().optional(),
    /** how it got here: pulled from GitHub, uploaded by a person, or pushed by a CI workflow */
    via: z.enum(["github", "upload", "ci", "check"]).optional(),
    /** CI provenance (workflow run that pushed it) */
    by: z.object({ ref: z.string().optional(), workflow: z.string().optional(), runId: z.string().optional(), actor: z.string().optional() }).optional(),
  })).optional(),
  /** what could not be checked (OSV unreachable, scan capped, …): never silently "all clear" */
  warnings: z.array(z.string()),
});
export type FindingSet = z.infer<typeof FindingSetSchema>;

/** A domain a repository's maintainers asked us to test, and the proof of ownership state. The token is public by design (it sits in DNS). */
export const DomainEntrySchema = z.object({
  domain: z.string(),
  token: z.string(),
  createdAt: z.number(),
  verifiedAt: z.number().optional(),
  verifiedVia: z.enum(["dns", "file"]).optional(),
  lastCheckAt: z.number().optional(),
  lastCheckCount: z.number().optional(),
});
export type DomainEntry = z.infer<typeof DomainEntrySchema>;

export interface SecurityContext {
  repo: string;
  files: string[];
  read(path: string): Promise<string | null>;
}

export const SEVERITY_WEIGHT: Record<Severity, number> = { critical: 25, high: 10, medium: 4, low: 1, info: 0 };
export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const worse = (a: Severity | null, b: Severity | null): Severity | null => (!a ? b : !b ? a : SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b);
