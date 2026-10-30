import type { Severity } from "../types";

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
const roundUp = (x: number) => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };

/** CVSS v3.0/v3.1 base score from a vector string, or null if it is not v3 or is malformed. (v4 is not computed here.) */
export function cvss3(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const m = Object.fromEntries(vector.split("/").slice(1).map((p) => p.split(":") as [string, string]));
  const scopeChanged = m.S === "C";
  const pr = m.PR === "N" ? 0.85 : m.PR === "L" ? (scopeChanged ? 0.68 : 0.62) : m.PR === "H" ? (scopeChanged ? 0.5 : 0.27) : undefined;
  if (AV[m.AV] === undefined || AC[m.AC] === undefined || pr === undefined || UI[m.UI] === undefined || CIA[m.C] === undefined || CIA[m.I] === undefined || CIA[m.A] === undefined || !["U", "C"].includes(m.S)) return null;
  const iss = 1 - (1 - CIA[m.C]) * (1 - CIA[m.I]) * (1 - CIA[m.A]);
  const impact = scopeChanged ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploit = 8.22 * AV[m.AV] * AC[m.AC] * pr * UI[m.UI];
  if (impact <= 0) return 0;
  return roundUp(Math.min(scopeChanged ? 1.08 * (impact + exploit) : impact + exploit, 10));
}

export const severityOfScore = (s: number): Severity => (s >= 9 ? "critical" : s >= 7 ? "high" : s >= 4 ? "medium" : s > 0 ? "low" : "info");

/** GitHub advisories label their own severity; OSV exposes it as database_specific.severity. */
export function severityOfLabel(l: string | undefined): Severity | null {
  switch ((l ?? "").toUpperCase()) { case "CRITICAL": return "critical"; case "HIGH": return "high"; case "MODERATE": case "MEDIUM": return "medium"; case "LOW": return "low"; default: return null; }
}
