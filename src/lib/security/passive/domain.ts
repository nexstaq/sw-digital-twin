import { randomBytes } from "node:crypto";
import { isIP } from "node:net";

export const VERIFY_LABEL = "_mission-control-verify";
export const VERIFY_PATH = "/.well-known/mission-control-verify.txt";

export type ParsedDomain = { ok: true; domain: string } | { ok: false; reason: string };

/**
 * A domain we are willing to test: a plain public hostname, nothing else. No scheme, port, path, credentials, IP address,
 * single-label name (`localhost`, `intranet`) or internal-looking suffix. Lowercased. This is the first of several gates, not the only one.
 */
export function parseDomain(input: string): ParsedDomain {
  let d = input.trim().toLowerCase().replace(/\.$/, "");
  if (!d) return { ok: false, reason: "Enter a domain, like staging.example.com." };
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(d)) { try { d = new URL(d).hostname; } catch { return { ok: false, reason: "That is not a valid address." }; } }
  if (/[\s/@:?#\\]/.test(d)) return { ok: false, reason: "Enter just the domain name: no path, port, or login in it." };
  if (d.length > 253) return { ok: false, reason: "That name is too long." };
  if (isIP(d) || /^\d+(\.\d+)*$/.test(d)) return { ok: false, reason: "IP addresses cannot be tested. Use a domain name you own." };
  const labels = d.split(".");
  if (labels.length < 2) return { ok: false, reason: "Use a full domain name, like staging.example.com." };
  if (!labels.every((l) => /^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(l))) return { ok: false, reason: "That is not a valid domain name." };
  if (!/^[a-z]{2,63}$|^xn--[a-z0-9-]{1,59}$/.test(labels.at(-1)!)) return { ok: false, reason: "That does not end in a real top-level domain." };
  if (/\.(local|localhost|internal|intranet|lan|home|corp|test|example|invalid|onion|arpa)$/.test(d) && !isTestHost(d)) return { ok: false, reason: "Internal and reserved names cannot be tested." };
  return { ok: true, domain: d };
}

/** The e2e suite uses a reserved `.test` name against a fixture server; real deployments never allow it. */
function isTestHost(d: string) {
  return !process.env.VERCEL && !!process.env.PASSIVE_CHECK_FIXTURE_URL && d.endsWith(".test");
}

/** A random, unguessable proof token. It is published openly (in DNS or a file), so it is not a secret: it proves control. */
export const newVerifyToken = () => `mc-verify-${randomBytes(16).toString("hex")}`;

export function instructions(domain: string, token: string) {
  return {
    dns: { type: "TXT", name: `${VERIFY_LABEL}.${domain}`, value: token },
    file: { url: `https://${domain}${VERIFY_PATH}`, contents: token },
  };
}
