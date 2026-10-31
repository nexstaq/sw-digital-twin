import type { Finding } from "../types";
import { analyzeProbe, PROBE_PATHS, toFindings, type PathResult, type Probe } from "./checks";
import { VERIFY_LABEL, VERIFY_PATH } from "./domain";
import { BlockedError, type Response } from "./net";
import type { Transport } from "./transport";

export type Verification = { ok: true; via: "dns" | "file" } | { ok: false; reasons: string[] };

/**
 * Proves the caller controls `domain`: the unguessable token must be in a DNS TXT record at `_mission-control-verify.<domain>`, or in
 * a file at `/.well-known/mission-control-verify.txt` over HTTPS (redirects are not followed, so it must be on this exact host).
 * Only someone who can change the domain's DNS or its web server can do either. Run before EVERY check, not just once.
 */
export async function verifyOwnership(domain: string, token: string, t: Transport): Promise<Verification> {
  const reasons: string[] = [];
  try {
    const txt = await t.txt(`${VERIFY_LABEL}.${domain}`);
    if (txt.some((v) => v.trim() === token)) return { ok: true, via: "dns" };
    reasons.push(`The DNS TXT record at ${VERIFY_LABEL}.${domain} was not found, or does not contain the token.`);
  } catch { reasons.push(`No DNS TXT record exists at ${VERIFY_LABEL}.${domain} yet (DNS changes can take a few minutes to appear).`); }

  try {
    const r = await t.request(domain, VERIFY_PATH, { scheme: "https", maxBytes: 512 });
    if (r.status === 200 && r.body.trim() === token) return { ok: true, via: "file" };
    reasons.push(r.status === 200 ? `The file at https://${domain}${VERIFY_PATH} exists but does not contain exactly the token.` : `https://${domain}${VERIFY_PATH} answered ${r.status}, not 200.`);
  } catch (e) {
    reasons.push(e instanceof BlockedError ? "That domain points at a private network address, so it cannot be checked." : `https://${domain}${VERIFY_PATH} could not be fetched (${e instanceof Error ? e.message : "error"}).`);
  }
  return { ok: false, reasons };
}

const sameHostRedirect = (domain: string, location: string | undefined): string | null => {
  if (!location) return null;
  try { const u = new URL(location, `https://${domain}/`); return u.protocol === "https:" && u.hostname.toLowerCase() === domain && !u.port ? `${u.pathname}${u.search}` || "/" : null; } catch { return null; }
};

export interface RunResult { findings: Finding[]; requests: number; notes: string[]; blocked?: boolean }

/**
 * About two dozen ordinary requests: the homepage (and where it redirects, on this host only), the certificate, plain HTTP, a CORS
 * probe, OPTIONS, a handful of well-known file paths, and a few DNS lookups. No attacks, no logins, no fuzzing, no brute force.
 * Sequential, bounded, and the calling route has already verified ownership.
 */
export async function runPassiveChecks(domain: string, t: Transport, o: { sleep?: (ms: number) => Promise<void> } = {}): Promise<RunResult> {
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const notes: string[] = [];
  let requests = 0;
  const probe: Probe = { domain, paths: [], dns: { mx: [] } };
  const guard = async <T,>(label: string, f: () => Promise<T>): Promise<T | { __error: string }> => {
    requests++;
    try { return await f(); } catch (e) {
      if (e instanceof BlockedError) throw e; // not a hiccup: stop everything
      return { __error: e instanceof Error ? e.message.slice(0, 120) : label };
    } finally { await sleep(80); } // gentle: never a burst
  };
  const isErr = (x: unknown): x is { __error: string } => typeof x === "object" && x !== null && "__error" in x;

  try {
    // 1) the homepage, following redirects only to this exact host
    let path = "/";
    let res: Response | { __error: string } = { __error: "not requested" };
    for (let hop = 0; hop < 3; hop++) {
      res = await guard("https", () => t.request(domain, path, { scheme: "https", maxBytes: 4096 }));
      if (isErr(res) || res.status < 300 || res.status >= 400) break;
      const next = sameHostRedirect(domain, typeof res.headers.location === "string" ? res.headers.location : undefined);
      if (!next) { notes.push("The homepage redirects to another address, so the response from this host itself was used."); break; }
      path = next;
    }
    probe.https = isErr(res) ? { error: res.__error } : { status: res.status, headers: res.headers };

    // 2) certificate
    const cert = await guard("cert", () => t.cert(domain));
    probe.cert = isErr(cert) ? { error: cert.__error } : cert;

    // 3) plain HTTP, not followed
    const plain = await guard("http", () => t.request(domain, "/", { scheme: "http", maxBytes: 1024 }));
    probe.http = isErr(plain) ? { error: plain.__error } : { status: plain.status, location: typeof plain.headers.location === "string" ? plain.headers.location : undefined };

    // 4) would the site let any origin read its responses?
    if (!isErr(res) && !probe.https.error) {
      const cors = await guard("cors", () => t.request(domain, "/", { scheme: "https", headers: { origin: "https://mission-control-probe.invalid" }, maxBytes: 512 }));
      if (!isErr(cors)) probe.cors = { acao: cors.headers["access-control-allow-origin"] as string | undefined, acac: cors.headers["access-control-allow-credentials"] as string | undefined };
      const opt = await guard("options", () => t.request(domain, "/", { scheme: "https", method: "OPTIONS", maxBytes: 512 }));
      if (!isErr(opt)) probe.options = { allow: opt.headers.allow as string | undefined };

      // 5) well-known paths. Only the first few KB are read, and none of it is kept beyond the signature check.
      for (const p of PROBE_PATHS) {
        const r = await guard(p, () => t.request(domain, p, { scheme: "https", maxBytes: 2048 }));
        if (isErr(r)) continue;
        probe.paths.push({ path: p, status: r.status, contentType: typeof r.headers["content-type"] === "string" ? r.headers["content-type"] : undefined, body: r.body, bytes: r.bytes } satisfies PathResult);
      }
    } else notes.push("The site could not be fetched over HTTPS, so its headers and files were not checked.");

    // 6) email protections, only meaningful when the domain receives mail
    requests++;
    try { probe.dns.mx = await t.mx(domain); } catch { /* no MX records: no mail */ }
    if (probe.dns.mx.length) {
      requests += 2;
      try { probe.dns.spf = (await t.txt(domain)).filter((v) => /^v=spf1\b/i.test(v)); } catch { probe.dns.spf = []; }
      try { probe.dns.dmarc = (await t.txt(`_dmarc.${domain}`)).filter((v) => /^v=DMARC1/i.test(v)); } catch { probe.dns.dmarc = []; }
    }
  } catch (e) {
    if (e instanceof BlockedError) return { findings: [], requests, notes: [`Refused: ${e.message}.`], blocked: true };
    throw e;
  }
  return { findings: toFindings(domain, analyzeProbe(probe)), requests, notes };
}
