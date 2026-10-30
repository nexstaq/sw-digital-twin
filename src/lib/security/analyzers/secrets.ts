import type { Finding, Severity, SecurityContext } from "../types";
import { fingerprint, isTestPath } from "../util";

interface Rule { kind: string; severity: Severity; re: RegExp; why: string; fix: string }

const ROTATE = "Treat it as leaked: revoke or rotate it now, then remove it from the code and from git history. Load it from an environment variable or a secret manager instead.";

/** Provider formats are specific, so a match is almost certainly real. The generic rule below is entropy-checked. */
const RULES: Rule[] = [
  { kind: "Private key", severity: "critical", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/, why: "A private key is committed. Anyone who can read the repository can impersonate whatever it protects.", fix: ROTATE },
  { kind: "AWS access key ID", severity: "critical", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, why: "An AWS access key ID is committed. Paired with its secret it grants access to your AWS account.", fix: ROTATE },
  { kind: "GitHub token", severity: "critical", re: /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/, why: "A GitHub token is committed. It can read or change repositories as the account that created it.", fix: ROTATE },
  { kind: "Stripe live secret key", severity: "critical", re: /\b[sr]k_live_[0-9A-Za-z]{16,}\b/, why: "A live Stripe secret key is committed. It can move real money.", fix: ROTATE },
  { kind: "Slack token", severity: "high", re: /\bxox[baprs]-[0-9A-Za-z-]{20,}\b/, why: "A Slack token is committed. It can read and post in your workspace.", fix: ROTATE },
  { kind: "Google API key", severity: "medium", re: /\bAIza[0-9A-Za-z_-]{35}\b/, why: "A Google API key is committed. Unrestricted keys can be abused for billable requests.", fix: "Restrict the key by referrer or IP in the Google Cloud console, and rotate it if it was unrestricted." },
  { kind: "npm token", severity: "high", re: /\bnpm_[A-Za-z0-9]{36}\b/, why: "An npm token is committed. It can publish packages as you.", fix: ROTATE },
  { kind: "Database URL with password", severity: "high", re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/'"]+:([^\s@/'"]{6,})@[^\s'"]+/, why: "A database connection string with an embedded password is committed.", fix: ROTATE },
];

const GENERIC = /(?:secret|token|passwd|password|api[_-]?key|auth[_-]?key|private[_-]?key)["']?\s*[:=]\s*["']([^"'\s]{12,})["']/i;
const FIXTURE_WORD = /(?:^|[-_.])(?:test|tests|fake|dummy|mock|mocked|example|sample|placeholder|notreal|not-a-real)(?:[-_.]|$)/i;
const PLACEHOLDER = /^(?:x+|\*+|<.*>|\$\{.*\}|%\(.*\)s|{{.*}}|your[_-]|changeme|change[_-]me|example|sample|dummy|placeholder|test|todo|redacted|secret|password|token|null|undefined|process\.env|os\.environ)/i;

const SKIP_FILE = /(^|\/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock)$|\.(min\.js|map|svg|png|jpe?g|gif|webp|ico|woff2?|ttf|eot|pdf|zip|gz|wasm|lock)$/i;
const EXAMPLE_FILE = /(^|\/)\.env\.(example|sample|template)$|\.(example|sample|template)$|(^|\/)(README|CHANGELOG)[^/]*$|\.mdx?$/i;

/** Hosts that mean "my own machine or my compose network", where a throwaway password is normal. */
const LOCAL_HOST = /^(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[?::1\]?|host\.docker\.internal|db|database|postgres|mysql|mariadb|mongo|mongodb|redis|rabbitmq|[\w-]+\.local)$/i;
const DEV_PASSWORD = /^(?:pass(?:word)?|postgres|root|admin|secret|changeme|example|test|dev|local|123456|password\d*|your[\w-]*|x+|\*+|<[^>]*>|\$\{[^}]*\})$/i;

/** Pulls host, user and password out of a connection string, without ever returning the password to a caller that logs it. */
export function dbUrlParts(text: string): { host: string; user: string; password: string } | null {
  const m = /:\/\/([^\s:@/'"]+):([^\s@/'"]+)@(\[[^\]]+\]|[^\s:/'"?]+)/.exec(text);
  return m ? { user: m[1], password: m[2], host: m[3] } : null;
}

/** "Looks like a name, not a secret": cookie names, header names, env var names (`authjs.session-token`, `x-api-key`). */
export const looksLikeIdentifier = (v: string) => /^[A-Za-z_][A-Za-z_.:/-]*$/.test(v) && /[-_.:/]/.test(v) && !/\d/.test(v);

export function entropy(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

/** First 4 characters and the length: enough to recognise it, nothing that can be used. */
export const maskSecret = (v: string) => `${v.slice(0, 4)}…(${v.length} chars)`;

/** For code excerpts shown in the UI: blank out anything that looks like a secret on the line. */
export function redactLine(line: string): string {
  let out = line;
  for (const r of RULES) out = out.replace(new RegExp(r.re.source, "g"), () => `[${r.kind} redacted]`);
  return out.replace(new RegExp(GENERIC.source, "gi"), (m, v: string) => (entropy(v) >= 3.2 && !PLACEHOLDER.test(v) ? m.replace(v, "[redacted]") : m));
}

export async function analyzeSecrets(ctx: SecurityContext): Promise<Finding[]> {
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const path of ctx.files) {
    if (SKIP_FILE.test(path)) continue;
    const text = await ctx.read(path);
    if (!text || text.includes("\u0000")) continue; // missing, too big, or binary
    const example = EXAMPLE_FILE.test(path);
    const test = isTestPath(path);
    const lines = text.split("\n");
    for (let i = 0; i < lines.length && i < 20_000; i++) {
      const line = lines[i];
      if (line.length > 2_000) continue; // minified blobs
      let hit: { kind: string; severity: Severity; why: string; fix: string; value: string } | null = null;
      for (const r of RULES) {
        const m = r.re.exec(line);
        if (m) { hit = { kind: r.kind, severity: r.severity, why: r.why, fix: r.fix, value: m[1] ?? m[0] }; break; }
      }
      if (hit?.kind === "Database URL with password") {
        const u = dbUrlParts(line);
        const local = !!u && LOCAL_HOST.test(u.host.replace(/^\[|\]$/g, ""));
        const throwaway = !!u && (DEV_PASSWORD.test(u.password) || u.password === u.user || FIXTURE_WORD.test(u.password));
        if (local && throwaway) continue; // a local dev database with a throwaway password: nothing to leak
        if (local || throwaway) hit = { ...hit, severity: "low", why: "A database connection string with a password is committed. The host and password look like local development, so this is probably harmless, but confirm that password is not reused anywhere real." };
      }
      if (!hit && !example) {
        const g = GENERIC.exec(line);
        if (g && !PLACEHOLDER.test(g[1]) && !FIXTURE_WORD.test(g[1]) && !looksLikeIdentifier(g[1]) && entropy(g[1]) >= 3.3 && !/\b(?:process\.env|os\.environ|getenv|import\.meta\.env)\b/.test(line)) {
          hit = { kind: "Hard-coded credential", severity: "medium", why: "A value that looks like a credential is assigned in code.", fix: "If it is real, rotate it and load it from the environment. If it is a placeholder, make that obvious (for example `changeme`).", value: g[1] };
        }
      }
      if (!hit) continue;
      if (example && hit.severity !== "critical") continue; // templates legitimately hold look-alikes
      const demoted = test || example;
      const id = fingerprint("secret", path, hit.kind, hit.value);
      if (seen.has(id)) continue;
      seen.add(id);
      const severity: Severity = demoted ? (hit.severity === "critical" ? "high" : hit.severity === "high" ? "medium" : "low") : hit.severity;
      out.push({
        id, ruleId: `SECRET/${hit.kind.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`, category: "secret", severity,
        title: `${hit.kind} committed in ${path.split("/").pop()}`, path, line: i + 1,
        reason: demoted ? `${hit.why} It sits in ${example ? "an example/template" : "a test or fixture"} file, so it may be a placeholder, but confirm it is not a real credential.` : hit.why,
        fix: hit.fix, cwe: ["CWE-798"], owasp: "A07:2021 Identification and Authentication Failures",
        confidence: demoted ? "low" : hit.kind === "Hard-coded credential" ? "medium" : "high",
        detail: { secretKind: hit.kind, masked: maskSecret(hit.value) },
      });
    }
  }
  return out;
}
