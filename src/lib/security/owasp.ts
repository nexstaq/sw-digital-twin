import { SEVERITY_RANK, worse, type Finding, type Severity } from "./types";

export type OwaspId = "A01" | "A02" | "A03" | "A04" | "A05" | "A06" | "A07" | "A08" | "A09" | "A10";

interface Category { id: OwaspId; name: string; /** can the checks in this product say anything about it? */ assessed: boolean; how: string }

/**
 * OWASP Top 10 (2021). `assessed: false` is not decoration: those categories are about design review and operations, which scans of a
 * repository cannot judge. They are shown as "not assessed", never as a reassuring green.
 */
export const OWASP: Category[] = [
  { id: "A01", name: "Broken Access Control", assessed: true, how: "path traversal, open redirects, endpoints that accept writes with no authentication check, overly open CORS, over-broad CI permissions" },
  { id: "A02", name: "Cryptographic Failures", assessed: true, how: "weak hashes, predictable tokens, disabled TLS verification, secrets baked into images, HTTPS and certificate checks" },
  { id: "A03", name: "Injection", assessed: true, how: "SQL and command injection, eval, cross-site scripting, script injection in CI" },
  { id: "A04", name: "Insecure Design", assessed: false, how: "needs a design and threat-model review, which no scan can do (the attack-path view is a starting point)" },
  { id: "A05", name: "Security Misconfiguration", assessed: true, how: "container and CI settings, insecure cookies, debug mode, missing security headers" },
  { id: "A06", name: "Vulnerable and Outdated Components", assessed: true, how: "known vulnerabilities in dependencies, unpinned base images" },
  { id: "A07", name: "Identification and Authentication Failures", assessed: true, how: "committed secrets and credentials, JWT misuse, missing authentication" },
  { id: "A08", name: "Software and Data Integrity Failures", assessed: true, how: "unpinned actions, unverified downloads, unsafe deserialization, pwn-request pipelines" },
  { id: "A09", name: "Security Logging and Monitoring Failures", assessed: false, how: "depends on how the running system is operated and monitored, which a repository scan cannot see" },
  { id: "A10", name: "Server-Side Request Forgery", assessed: true, how: "server-side fetches of URLs taken from the request" },
];
const BY_ID = new Map(OWASP.map((c) => [c.id, c]));

/** CWE -> OWASP 2021 category, for findings from tools that did not say (imports, GitHub alerts). Only well-established mappings. */
const CWE_TO_OWASP: Record<number, OwaspId> = {
  // A01 Broken Access Control
  22: "A01", 23: "A01", 35: "A01", 59: "A01", 200: "A01", 201: "A01", 219: "A01", 264: "A01", 275: "A01", 276: "A01", 284: "A01", 285: "A01", 352: "A01", 359: "A01", 377: "A01", 425: "A01", 441: "A01", 497: "A01", 538: "A01", 540: "A01", 548: "A01", 552: "A01", 566: "A01", 601: "A01", 639: "A01", 651: "A01", 668: "A01", 706: "A01", 862: "A01", 863: "A01", 913: "A01", 922: "A01",
  // A02 Cryptographic Failures
  261: "A02", 296: "A02", 310: "A02", 319: "A02", 321: "A02", 322: "A02", 323: "A02", 324: "A02", 325: "A02", 326: "A02", 327: "A02", 328: "A02", 329: "A02", 330: "A02", 331: "A02", 335: "A02", 336: "A02", 337: "A02", 338: "A02", 340: "A02", 347: "A02", 523: "A02", 720: "A02", 757: "A02", 759: "A02", 760: "A02", 780: "A02", 818: "A02", 916: "A02",
  // A03 Injection
  20: "A03", 74: "A03", 75: "A03", 77: "A03", 78: "A03", 79: "A03", 80: "A03", 83: "A03", 87: "A03", 88: "A03", 89: "A03", 90: "A03", 91: "A03", 93: "A03", 94: "A03", 95: "A03", 96: "A03", 97: "A03", 98: "A03", 99: "A03", 100: "A03", 113: "A03", 116: "A03", 138: "A03", 184: "A03", 470: "A03", 471: "A03", 564: "A03", 610: "A03", 643: "A03", 644: "A03", 652: "A03", 917: "A03",
  // A04 Insecure Design
  73: "A04", 183: "A04", 209: "A04", 213: "A04", 235: "A04", 256: "A04", 257: "A04", 266: "A04", 269: "A04", 280: "A04", 311: "A04", 312: "A04", 313: "A04", 316: "A04", 419: "A04", 430: "A04", 434: "A04", 444: "A04", 451: "A04", 472: "A04", 501: "A04", 522: "A04", 525: "A04", 539: "A04", 579: "A04", 598: "A04", 602: "A04", 642: "A04", 646: "A04", 650: "A04", 653: "A04", 656: "A04", 657: "A04", 799: "A04", 807: "A04", 840: "A04", 841: "A04", 927: "A04", 1021: "A04", 1173: "A04",
  // A05 Security Misconfiguration
  2: "A05", 11: "A05", 13: "A05", 15: "A05", 16: "A05", 260: "A05", 315: "A05", 520: "A05", 526: "A05", 537: "A05", 541: "A05", 547: "A05", 611: "A05", 614: "A05", 756: "A05", 776: "A05", 942: "A05", 1004: "A05", 1032: "A05", 1174: "A05", 215: "A05", 489: "A05", 693: "A05", 
  // A06 Vulnerable and Outdated Components
  937: "A06", 1035: "A06", 1104: "A06",
  // A07 Identification and Authentication Failures
  255: "A07", 259: "A07", 287: "A07", 306: "A07", 288: "A07", 290: "A07", 294: "A07", 297: "A07", 300: "A07", 302: "A07", 304: "A07", 307: "A07", 346: "A07", 384: "A07", 521: "A07", 613: "A07", 620: "A07", 640: "A07", 295: "A07", 798: "A07", 940: "A07", 1216: "A07",
  // A08 Software and Data Integrity Failures
  345: "A08", 353: "A08", 426: "A08", 494: "A08", 502: "A08", 565: "A08", 784: "A08", 829: "A08", 830: "A08", 915: "A08", 
  // A09 Security Logging and Monitoring Failures
  117: "A09", 223: "A09", 532: "A09", 778: "A09",
  // A10 Server-Side Request Forgery
  918: "A10",
};

const cweNum = (c: string) => Number(/(\d{1,5})/.exec(c)?.[1]);

/** The OWASP 2021 category of a finding: what its own analyzer said, else derived from its CWE, else null. */
export function owaspOf(f: Pick<Finding, "owasp" | "cwe">): OwaspId | null {
  const m = /^(A(?:0[1-9]|10)):2021/.exec(f.owasp ?? "");
  if (m) return m[1] as OwaspId;
  for (const c of f.cwe) { const id = CWE_TO_OWASP[cweNum(c)]; if (id) return id; }
  return null;
}

export interface OwaspRow extends Category {
  total: number;
  counts: Record<Severity, number>;
  worst: Severity | null;
  /** finding ids */
  findings: string[];
}

/** One row per OWASP category, always all ten, so a gap is visible as a gap. */
export function owaspSummary(findings: Finding[]): { rows: OwaspRow[]; unmapped: number } {
  const rows: OwaspRow[] = OWASP.map((c) => ({ ...c, total: 0, counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, worst: null, findings: [] }));
  const byId = new Map(rows.map((r) => [r.id, r]));
  let unmapped = 0;
  for (const f of findings) {
    const id = owaspOf(f);
    const row = id && byId.get(id);
    if (!row) { unmapped++; continue; }
    row.total++; row.counts[f.severity]++; row.worst = worse(row.worst, f.severity); row.findings.push(f.id);
  }
  return { rows, unmapped };
}

export interface CweRow { cwe: string; count: number; worst: Severity; owasp: OwaspId | null }

/** The weaknesses that occur most, worst first. */
export function cweSummary(findings: Finding[], limit = 10): CweRow[] {
  const map = new Map<string, CweRow>();
  for (const f of findings) {
    for (const raw of f.cwe) {
      const n = cweNum(raw);
      if (!Number.isFinite(n)) continue;
      const cwe = `CWE-${n}`;
      const cur = map.get(cwe);
      if (cur) { cur.count++; if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[cur.worst]) cur.worst = f.severity; }
      else map.set(cwe, { cwe, count: 1, worst: f.severity, owasp: CWE_TO_OWASP[n] ?? null });
    }
  }
  return [...map.values()].sort((a, b) => SEVERITY_RANK[b.worst] - SEVERITY_RANK[a.worst] || b.count - a.count || Number(a.cwe.slice(4)) - Number(b.cwe.slice(4))).slice(0, limit);
}

export const owaspCategory = (id: OwaspId) => BY_ID.get(id)!;
