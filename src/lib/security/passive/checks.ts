import { fingerprint } from "../util";
import type { Finding, Severity } from "../types";
import type { CertInfo } from "./net";

export interface PathResult { path: string; status: number; contentType?: string; /** the first few KB only */ body: string; bytes: number }
export interface Probe {
  domain: string;
  /** the homepage over HTTPS. `error` set means it could not be fetched. */
  https?: { status?: number; headers?: Record<string, string | string[] | undefined>; error?: string };
  /** plain HTTP: where it goes, or that it answers directly */
  http?: { status?: number; location?: string; error?: string };
  /** the homepage again, with a made-up Origin, to see whether the server reflects it */
  cors?: { acao?: string; acac?: string };
  options?: { allow?: string };
  cert?: CertInfo | { error: string };
  paths: PathResult[];
  dns: { mx: string[]; spf?: string[]; dmarc?: string[] };
}

interface Hit { ruleId: string; severity: Severity; title: string; url: string; reason: string; fix: string; cwe: string[]; owasp: string; key?: string; confidence?: "high" | "medium" | "low" }

const A02 = "A02:2021 Cryptographic Failures", A05 = "A05:2021 Security Misconfiguration", A07 = "A07:2021 Identification and Authentication Failures";

const h = (headers: Record<string, string | string[] | undefined> | undefined, name: string): string | undefined => { const v = headers?.[name]; return Array.isArray(v) ? v.join(", ") : v; };

// ---------- exposed files: a signature must match, so a site that answers 200 to everything is not a false alarm ----------

interface Exposed { path: string; sig: (body: string) => boolean; severity: Severity; title: string; reason: string; cwe: string[]; html?: boolean }
const FIX_FILE = "Remove it from the public web root, deny the path in your server or CDN config, and treat anything it contained as leaked: rotate those credentials.";
export const EXPOSED: Exposed[] = [
  { path: "/.git/HEAD", sig: (b) => /^ref: refs\/heads\/[\w./-]+/m.test(b), severity: "high", title: "Git repository is publicly readable", reason: "Anyone can download your repository's history, including source code and any secret that was ever committed.", cwe: ["CWE-527"] },
  { path: "/.git/config", sig: (b) => /\[core\]/.test(b), severity: "high", title: "Git configuration is publicly readable", reason: "It shows the repository's remotes and settings and signals that the whole .git folder is probably exposed.", cwe: ["CWE-527"] },
  ...[".env", ".env.local", ".env.production"].map((f): Exposed => ({ path: `/${f}`, sig: (b) => /^[A-Z][A-Z0-9_]{2,}\s*=/m.test(b), severity: "high", title: `${f} file is publicly readable`, reason: "Environment files hold database passwords, API keys and signing secrets. Anyone can read this one.", cwe: ["CWE-538"] })),
  { path: "/.DS_Store", sig: (b) => b.includes("Bud1"), severity: "low", title: "macOS .DS_Store file is publicly readable", reason: "It lists the names of files and folders on the server, helping an attacker find things that are not linked.", cwe: ["CWE-538"] },
  ...["/backup.sql", "/dump.sql", "/db.sql"].map((p): Exposed => ({ path: p, sig: (b) => /CREATE TABLE|INSERT INTO|DROP TABLE/i.test(b), severity: "high", title: `Database dump ${p.slice(1)} is publicly readable`, reason: "A database export contains your users' data.", cwe: ["CWE-530"] })),
  { path: "/backup.zip", sig: (b) => b.startsWith("PK\u0003\u0004"), severity: "high", title: "backup.zip is publicly downloadable", reason: "A backup archive usually contains source code, configuration and data.", cwe: ["CWE-530"] },
  { path: "/phpinfo.php", sig: (b) => /phpinfo\(\)|PHP Version/.test(b), severity: "medium", title: "phpinfo() page is public", reason: "It reveals the server's PHP version, modules, paths and environment, which helps an attacker plan.", cwe: ["CWE-200"], html: true },
  { path: "/server-status", sig: (b) => /Apache Server Status/.test(b), severity: "medium", title: "Apache server-status page is public", reason: "It exposes live requests, client addresses and URLs.", cwe: ["CWE-200"], html: true },
  { path: "/actuator/env", sig: (b) => /"propertySources"/.test(b), severity: "high", title: "Spring Boot /actuator/env is public", reason: "It dumps the application's configuration, which often includes credentials.", cwe: ["CWE-200"] },
  ...["/wp-config.php.bak", "/config.php.bak"].map((p): Exposed => ({ path: p, sig: (b) => /DB_PASSWORD|<\?php/.test(b), severity: "high", title: `${p.slice(1)} is publicly readable`, reason: "An editor or backup copy of a config file is served as plain text, exposing its credentials.", cwe: ["CWE-530"] })),
  { path: "/package.json", sig: (b) => /"(dependencies|devDependencies)"\s*:/.test(b), severity: "low", title: "package.json is publicly readable", reason: "It tells an attacker exactly which libraries and versions you run, so they can look for known flaws.", cwe: ["CWE-200"] },
];
export const SECURITY_TXT = "/.well-known/security.txt";
export const PROBE_PATHS = [...EXPOSED.map((e) => e.path), SECURITY_TXT];

// ---------- cookies ----------

export interface CookieFlags { name: string; secure: boolean; httpOnly: boolean; sameSite?: string }
export function parseSetCookie(line: string): CookieFlags | null {
  const [pair, ...attrs] = line.split(";").map((s) => s.trim());
  const name = pair.split("=")[0]?.trim();
  if (!name) return null;
  const a = attrs.map((x) => x.toLowerCase());
  return { name, secure: a.includes("secure"), httpOnly: a.includes("httponly"), sameSite: a.find((x) => x.startsWith("samesite="))?.slice(9) };
}
const SESSIONISH = /(sess|sid|token|auth|jwt|login|csrf|xsrf|remember)/i;

// ---------- the rules ----------

export function analyzeProbe(p: Probe): Hit[] {
  const out: Hit[] = [];
  const base = `https://${p.domain}`;
  const hit = (x: Omit<Hit, "url"> & { url?: string }) => out.push({ url: base + "/", ...x });

  // reachability and certificate
  if (p.https?.error) hit({ ruleId: "WEB/https-unavailable", severity: "high", title: "The site could not be reached over HTTPS", reason: `A secure connection to ${p.domain} failed (${p.https.error}). Visitors either cannot reach it or are sent over unencrypted HTTP.`, fix: "Serve the site over HTTPS with a valid certificate on port 443.", cwe: ["CWE-319"], owasp: A02, confidence: "medium" });
  const c = p.cert && !("error" in p.cert) ? p.cert : undefined;
  if (c) {
    if (!c.authorized) hit({ ruleId: "WEB/cert-untrusted", severity: "high", title: "The TLS certificate is not trusted by browsers", reason: `Browsers will warn visitors: ${c.authorizationError ?? "the certificate could not be verified"}. It may be expired, for another name, self-signed or missing an intermediate certificate.`, fix: "Install a certificate from a public authority (Let's Encrypt is free) that covers this exact name, with its full chain.", cwe: ["CWE-295"], owasp: A02 });
    if (c.daysLeft !== undefined) {
      if (c.daysLeft < 0) hit({ ruleId: "WEB/cert-expired", severity: "high", title: "The TLS certificate has expired", reason: `It expired ${Math.abs(c.daysLeft)} day${Math.abs(c.daysLeft) === 1 ? "" : "s"} ago. Browsers block the site.`, fix: "Renew it now and set up automatic renewal.", cwe: ["CWE-298"], owasp: A02 });
      else if (c.daysLeft <= 30) hit({ ruleId: "WEB/cert-expiring", severity: c.daysLeft <= 14 ? "medium" : "low", title: `The TLS certificate expires in ${c.daysLeft} day${c.daysLeft === 1 ? "" : "s"}`, reason: "When it expires, browsers will block the site until it is renewed.", fix: "Renew it, and set up automatic renewal so this cannot recur.", cwe: ["CWE-298"], owasp: A02, key: "expiring" });
    }
    if (c.keyBits && !c.ec && c.keyBits >= 512 && c.keyBits < 2048) hit({ ruleId: "WEB/cert-weak-key", severity: "medium", title: `The TLS certificate uses a weak ${c.keyBits}-bit RSA key`, reason: "RSA keys under 2048 bits can be broken with modest resources.", fix: "Reissue the certificate with a 2048-bit or larger RSA key, or an elliptic-curve key.", cwe: ["CWE-326"], owasp: A02 });
    if (c.protocol && /^(SSLv\d|TLSv1(\.1)?)$/.test(c.protocol)) hit({ ruleId: "WEB/tls-old-protocol", severity: "medium", title: `The server negotiated an outdated protocol (${c.protocol})`, reason: "TLS 1.0 and 1.1 have known weaknesses and are rejected by modern security guidance.", fix: "Allow only TLS 1.2 and 1.3.", cwe: ["CWE-326"], owasp: A02 });
  }

  // plain HTTP
  if (p.http && !p.http.error) {
    const s = p.http.status ?? 0;
    if (s >= 200 && s < 300) hit({ ruleId: "WEB/http-no-redirect", severity: "medium", url: `http://${p.domain}/`, title: "The site answers over plain HTTP instead of redirecting to HTTPS", reason: "Anyone on the network path (public Wi-Fi, a hostile router) can read and alter what visitors send and receive.", fix: "Redirect all HTTP requests to HTTPS (301), and send an HSTS header.", cwe: ["CWE-319"], owasp: A02 });
    else if (s >= 300 && s < 400 && p.http.location && /^http:\/\//i.test(p.http.location)) hit({ ruleId: "WEB/http-redirect-insecure", severity: "low", url: `http://${p.domain}/`, title: "HTTP redirects to another HTTP address", reason: "The redirect does not move visitors onto an encrypted connection.", fix: "Redirect to the https:// address.", cwe: ["CWE-319"], owasp: A02 });
  }

  // headers on the HTTPS homepage
  const hd = p.https?.error ? undefined : p.https?.headers;
  if (hd) {
    const hsts = h(hd, "strict-transport-security");
    if (!hsts) hit({ ruleId: "WEB/hsts-missing", severity: "medium", title: "No HSTS header", reason: "Without Strict-Transport-Security, a browser's first request can still go over plain HTTP, where it can be intercepted and downgraded.", fix: "Send `Strict-Transport-Security: max-age=63072000; includeSubDomains` on every HTTPS response.", cwe: ["CWE-319"], owasp: A02 });
    else { const age = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? 0); if (age < 15_552_000) hit({ ruleId: "WEB/hsts-weak", severity: "low", title: "HSTS lifetime is short", reason: `max-age is ${age} seconds. Browsers forget the rule quickly, which leaves the downgrade window open.`, fix: "Use at least 15552000 (180 days), ideally 63072000.", cwe: ["CWE-319"], owasp: A02 }); }

    const csp = h(hd, "content-security-policy");
    if (!csp) hit({ ruleId: "WEB/csp-missing", severity: "medium", title: "No Content-Security-Policy", reason: "A CSP limits what scripts a page may run, which contains most cross-site scripting bugs. Without one, any injected script runs freely.", fix: "Add a Content-Security-Policy that allows scripts only from your own origin (and nonces or hashes for inline ones).", cwe: ["CWE-693"], owasp: A05 });
    else {
      // script-src governs scripts when it is present; default-src only applies when it is not
      const directive = (name: string) => new RegExp(`(?:^|;)\\s*${name}\\s+([^;]*)`, "i").exec(csp)?.[1];
      const script = directive("script-src") ?? directive("default-src") ?? "";
      const hasNonce = /'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(script);
      if ((/'unsafe-inline'/.test(script) && !hasNonce) || /'unsafe-eval'/.test(script) || /(^|\s)\*(\s|$)/.test(script) || /(^|\s)(data:|https:)(\s|$)/.test(script)) {
        hit({ ruleId: "WEB/csp-weak", severity: "low", title: "The Content-Security-Policy is weak", reason: "It allows inline scripts, `eval`, or any source for scripts, which defeats much of its protection against injected code.", fix: "Remove 'unsafe-inline' and 'unsafe-eval' from script-src (use nonces or hashes), and avoid `*`, `data:` and bare `https:` for scripts.", cwe: ["CWE-693"], owasp: A05 });
      }
    }
    if (!/nosniff/i.test(h(hd, "x-content-type-options") ?? "")) hit({ ruleId: "WEB/nosniff-missing", severity: "low", title: "No X-Content-Type-Options: nosniff", reason: "Browsers may guess a file's type and run a harmless-looking upload as a script.", fix: "Send `X-Content-Type-Options: nosniff`.", cwe: ["CWE-693"], owasp: A05 });
    if (!h(hd, "x-frame-options") && !/frame-ancestors/i.test(csp ?? "")) hit({ ruleId: "WEB/clickjacking", severity: "low", title: "The site can be shown inside another site's frame", reason: "An attacker can overlay your pages invisibly and trick visitors into clicking buttons they cannot see (clickjacking).", fix: "Send `Content-Security-Policy: frame-ancestors 'none'` (or 'self'), and `X-Frame-Options: DENY` for old browsers.", cwe: ["CWE-1021"], owasp: A05 });
    const server = h(hd, "server");
    if (server && /\/\d/.test(server)) hit({ ruleId: "WEB/server-version", severity: "low", title: `The Server header reveals a version (${server.slice(0, 60)})`, reason: "Exact software versions let an attacker look up known vulnerabilities for them.", fix: "Remove the version from the Server header (for example `server_tokens off;` in nginx, `ServerTokens Prod` in Apache).", cwe: ["CWE-200"], owasp: A05 });
    const powered = h(hd, "x-powered-by");
    if (powered) hit({ ruleId: "WEB/powered-by", severity: "low", title: `X-Powered-By reveals the framework (${powered.slice(0, 60)})`, reason: "It tells an attacker which technology to target.", fix: "Disable the X-Powered-By header in your framework.", cwe: ["CWE-200"], owasp: A05 });

    // cookies
    const raw = hd["set-cookie"];
    const lines = Array.isArray(raw) ? raw : raw ? [raw] : [];
    const seen = new Set<string>();
    for (const line of lines) {
      const ck = parseSetCookie(line);
      if (!ck || seen.has(ck.name)) continue;
      seen.add(ck.name);
      const sess = SESSIONISH.test(ck.name);
      const missing: string[] = [];
      if (!ck.secure) missing.push("Secure");
      if (!ck.httpOnly && sess) missing.push("HttpOnly");
      if (!ck.sameSite) missing.push("SameSite");
      if (!missing.length) continue;
      const serious = sess && missing.some((m) => m !== "SameSite");
      hit({ ruleId: "WEB/cookie-insecure", severity: serious ? "medium" : "low", key: ck.name, title: `Cookie “${ck.name.slice(0, 40)}” is missing ${missing.join(", ")}`,
        reason: `${!ck.secure ? "Without Secure, the browser also sends it over plain HTTP, where it can be read. " : ""}${!ck.httpOnly && sess ? "Without HttpOnly, any script on the page (including an injected one) can steal it. " : ""}${!ck.sameSite ? "Without SameSite, other sites can make requests that carry it (cross-site request forgery)." : ""}`.trim(),
        fix: `Set the cookie with ${missing.map((m) => (m === "SameSite" ? "SameSite=Lax (or Strict)" : m)).join(", ")}.`, cwe: missing.includes("SameSite") && missing.length === 1 ? ["CWE-1275"] : ["CWE-614", "CWE-1004"], owasp: A05 });
    }
  }

  // CORS
  if (p.cors?.acao) {
    const creds = /^true$/i.test(p.cors.acac ?? "");
    if (p.cors.acao === "https://mission-control-probe.invalid") hit({ ruleId: "WEB/cors-reflects-origin", severity: creds ? "high" : "medium", title: creds ? "CORS reflects any origin and allows credentials" : "CORS reflects any origin", reason: creds ? "Any website can make authenticated requests as your signed-in visitors and read the responses." : "Any website can read this site's responses from a visitor's browser.", fix: "Allow only an explicit list of origins you trust, never the request's own Origin value.", cwe: ["CWE-942"], owasp: A05 });
    else if (p.cors.acao === "*" && creds) hit({ ruleId: "WEB/cors-wildcard-credentials", severity: "high", title: "CORS allows any origin together with credentials", reason: "This combination is invalid in browsers but signals a misconfigured policy that may be fixed up incorrectly later.", fix: "List the exact origins you trust.", cwe: ["CWE-942"], owasp: A05 });
  }
  if (/\bTRACE\b/i.test(p.options?.allow ?? "")) hit({ ruleId: "WEB/trace-enabled", severity: "low", title: "The HTTP TRACE method is enabled", reason: "TRACE echoes requests back and has been used to steal headers in cross-site attacks.", fix: "Disable the TRACE method on the server.", cwe: ["CWE-16"], owasp: A05 });

  // exposed files, judged by signature
  for (const r of p.paths) {
    const e = EXPOSED.find((x) => x.path === r.path);
    if (!e || r.status !== 200) continue;
    if (!e.html && /text\/html/i.test(r.contentType ?? "")) continue; // a site that returns its homepage for every path is not leaking a file
    if (!e.sig(r.body)) continue;
    hit({ ruleId: "WEB/exposed-file", severity: e.severity, url: `${base}${e.path}`, key: e.path, title: e.title, reason: e.reason, fix: FIX_FILE, cwe: e.cwe, owasp: A05, confidence: "high" });
  }
  const st = p.paths.find((r) => r.path === SECURITY_TXT);
  if (st && st.status === 404) hit({ ruleId: "WEB/no-security-txt", severity: "info", url: `${base}${SECURITY_TXT}`, title: "No security.txt", reason: "A security.txt file tells researchers how to report a vulnerability to you privately. Without one, reports may go nowhere or become public.", fix: "Publish /.well-known/security.txt with a Contact line (see securitytxt.org).", cwe: [], owasp: A05, confidence: "high" });

  // email protections (only meaningful for a domain that receives mail)
  if (p.dns.mx.length) {
    const spf = (p.dns.spf ?? []).find((t) => /^v=spf1\b/i.test(t));
    if (!spf) hit({ ruleId: "WEB/spf-missing", severity: "medium", url: `dns:${p.domain}`, title: "No SPF record", reason: "Without SPF, anyone can send email that claims to be from this domain, which is the basis of most phishing against your customers.", fix: `Publish a TXT record such as \`v=spf1 include:<your mail provider> -all\`.`, cwe: ["CWE-290"], owasp: A07 });
    else if (/(^|\s)\+all\b/i.test(spf) || /\?all\b/i.test(spf)) hit({ ruleId: "WEB/spf-permissive", severity: /\+all/i.test(spf) ? "high" : "low", url: `dns:${p.domain}`, title: "The SPF record allows anyone to send as this domain", reason: "`+all` (or `?all`) tells receivers every server is authorised, which makes SPF useless.", fix: "End the record with `-all` (or `~all` while you verify).", cwe: ["CWE-290"], owasp: A07 });
    const dmarc = (p.dns.dmarc ?? []).find((t) => /^v=DMARC1/i.test(t));
    if (!dmarc) hit({ ruleId: "WEB/dmarc-missing", severity: "medium", url: `dns:_dmarc.${p.domain}`, title: "No DMARC record", reason: "DMARC tells receivers what to do with email that fails SPF/DKIM, and sends you reports. Without it, spoofed mail is delivered.", fix: "Publish a TXT record at _dmarc with `v=DMARC1; p=quarantine; rua=mailto:you@yourdomain`.", cwe: ["CWE-290"], owasp: A07 });
    else if (/\bp=none\b/i.test(dmarc)) hit({ ruleId: "WEB/dmarc-none", severity: "low", url: `dns:_dmarc.${p.domain}`, title: "DMARC is in monitor-only mode (p=none)", reason: "Spoofed mail is reported but still delivered.", fix: "Move to p=quarantine, then p=reject, once the reports look clean.", cwe: ["CWE-290"], owasp: A07 });
  }
  return out;
}

/** Hits become findings in the "live testing" category, located at the URL they concern. No response body is ever kept. */
export function toFindings(domain: string, hits: Hit[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const x of hits) {
    const id = fingerprint("passive", domain, x.ruleId, x.key ?? "");
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      id, ruleId: x.ruleId, category: "runtime", severity: x.severity, title: x.title, path: x.url, reason: x.reason, fix: x.fix, cwe: x.cwe, owasp: x.owasp,
      confidence: x.confidence ?? "high", detail: { source: `passive:${domain}`, sourceName: domain },
    });
  }
  return out;
}
