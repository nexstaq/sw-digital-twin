import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import { BlockList, isIP } from "node:net";
import tls from "node:tls";

/**
 * Outbound networking for checks against a hostname a USER typed. That is a server-side request forgery risk, so every request goes
 * through here: the host is resolved by us, EVERY address it returns must be public, the connection uses the address we validated
 * (so DNS cannot change its answer between check and use), and the response is bounded.
 */

const blocked = new BlockList();
for (const [net, bits] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blocked.addSubnet(net, bits, "ipv4");
for (const [net, bits] of [
  ["::", 128], ["::1", 128], ["64:ff9b::", 96], ["100::", 64], ["2001::", 32], ["2001:db8::", 32], ["2002::", 16], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8],
] as const) blocked.addSubnet(net, bits, "ipv6");

/** True only for a globally routable address. IPv4-mapped IPv6 (`::ffff:127.0.0.1`) is judged by its IPv4 part. */
export function isPublicIp(ip: string): boolean {
  const family = isIP(ip);
  if (!family) return false;
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  if (mapped) return isPublicIp(mapped[1]);
  const hexMapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ip);
  if (hexMapped) { const a = parseInt(hexMapped[1], 16), b = parseInt(hexMapped[2], 16); return isPublicIp(`${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`); }
  return !blocked.check(ip, family === 4 ? "ipv4" : "ipv6");
}

export class BlockedError extends Error { constructor(msg: string) { super(msg); this.name = "BlockedError"; } }

type Resolve = (hostname: string) => Promise<{ address: string; family: number }[]>;
const systemResolve: Resolve = (h) => dns.promises.lookup(h, { all: true, verbatim: true });

export interface NetOptions {
  /** tests only: allow loopback so a local server can stand in for the internet. Production code never sets this. */
  allowPrivate?: boolean;
  /** tests only, and only honoured together with `allowPrivate`: the port of the local stand-in server */
  testPort?: number;
  resolve?: Resolve;
}

/** A `lookup` for http(s).request that refuses any host with a non-public address, and hands back the validated one. */
export function guardedLookup(o: NetOptions = {}) {
  const resolve = o.resolve ?? systemResolve;
  return (hostname: string, options: unknown, cb: (err: Error | null, address?: string | { address: string; family: number }[], family?: number) => void) => {
    const all = typeof options === "object" && options !== null && (options as { all?: boolean }).all;
    resolve(hostname).then((addrs) => {
      if (!addrs.length) return cb(new BlockedError(`no address for ${hostname}`));
      if (!o.allowPrivate) {
        const bad = addrs.find((a) => !isPublicIp(a.address));
        if (bad) return cb(new BlockedError(`${hostname} resolves to a non-public address, so it will not be contacted`)); // ANY private answer blocks the host
      }
      const first = addrs.find((a) => a.family === 4) ?? addrs[0];
      return all ? cb(null, addrs.map((a) => ({ address: a.address, family: a.family }))) : cb(null, first.address, first.family);
    }, (e) => cb(e instanceof Error ? e : new Error("lookup failed")));
  };
}

export const USER_AGENT = "MissionControl-PassiveCheck/1.0 (+https://github.com/nexstaq/sw-digital-twin; checks only domains whose owner asked for it)";

export interface Response { status: number; headers: Record<string, string | string[] | undefined>; /** first `maxBytes` of the body as text */ body: string; bytes: number; truncated: boolean }
export interface RequestOptions extends NetOptions { method?: "GET" | "HEAD" | "OPTIONS"; headers?: Record<string, string>; timeoutMs?: number; maxBytes?: number; scheme?: "http" | "https" }

/**
 * One bounded request to `host` (the validated domain) and `path`. Standard ports only, the host is the only thing it will connect to,
 * redirects are NOT followed (the caller decides), no cookies, no compression, no connection reuse.
 */
export function safeRequest(host: string, path: string, o: RequestOptions = {}): Promise<Response> {
  const scheme = o.scheme ?? "https";
  if (!/^\/[\w\-./~%@!$&'()*+,;=:]*(\?[\w\-./~%@!$&'()*+,;=:?]*)?$/.test(path)) return Promise.reject(new BlockedError("unsupported path"));
  if (isIP(host) || /[\s/@:?#\\]/.test(host)) return Promise.reject(new BlockedError("not a hostname"));
  const maxBytes = o.maxBytes ?? 8192;
  return new Promise((resolve, reject) => {
    const mod = scheme === "https" ? https : http;
    const req = mod.request({
      host, port: o.allowPrivate && o.testPort ? o.testPort : scheme === "https" ? 443 : 80, path, method: o.method ?? "GET", agent: false, lookup: guardedLookup(o) as never, servername: host,
      headers: { "user-agent": USER_AGENT, accept: "*/*", connection: "close", "accept-encoding": "identity", ...o.headers },
      timeout: o.timeoutMs ?? 8000,
    }, (res) => {
      const chunks: Buffer[] = [];
      let bytes = 0, truncated = false, done = false;
      const finish = () => { if (done) return; done = true; resolve({ status: res.statusCode ?? 0, headers: res.headers as Response["headers"], body: Buffer.concat(chunks).toString("utf8"), bytes, truncated }); };
      res.on("data", (c: Buffer) => {
        bytes += c.length;
        if (bytes <= maxBytes) chunks.push(c);
        else { truncated = true; res.destroy(); finish(); } // never read more than we asked for
      });
      res.on("end", finish);
      res.on("close", finish);
      res.on("error", () => finish());
    });
    req.on("timeout", () => req.destroy(new Error("timed out")));
    req.on("error", (e) => reject(e));
    req.end();
  });
}

export interface CertInfo {
  authorized: boolean;
  authorizationError?: string;
  protocol?: string | null;
  /** days until the certificate expires (negative: already expired) */
  daysLeft?: number;
  notBefore?: string;
  issuer?: string;
  subject?: string;
  keyBits?: number;
  /** an elliptic-curve key: 256 bits is strong for EC and would be broken for RSA, so size alone cannot be judged */
  ec?: boolean;
  names?: string[];
}

const one = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

/** Connects with TLS to read what the server presents, WITHOUT trusting it, so a broken certificate can be reported instead of failing. */
export function safeCert(host: string, o: NetOptions & { timeoutMs?: number; now?: number } = {}): Promise<CertInfo> {
  if (isIP(host) || /[\s/@:?#\\]/.test(host)) return Promise.reject(new BlockedError("not a hostname"));
  return new Promise((resolve, reject) => {
    const sock = tls.connect({ host, port: o.allowPrivate && o.testPort ? o.testPort : 443, servername: host, rejectUnauthorized: false, lookup: guardedLookup(o) as never, timeout: o.timeoutMs ?? 8000 }, () => {
      const c = sock.getPeerCertificate();
      const now = o.now ?? Date.now();
      const info: CertInfo = {
        authorized: sock.authorized, authorizationError: sock.authorized ? undefined : String(sock.authorizationError ?? "unverified"), protocol: sock.getProtocol(),
        ...(c && c.valid_to ? { daysLeft: Math.floor((Date.parse(c.valid_to) - now) / 86_400_000), notBefore: c.valid_from, issuer: one(c.issuer?.O ?? c.issuer?.CN), subject: one(c.subject?.CN), keyBits: c.bits, ec: !!c.asn1Curve, names: (c.subjectaltname ?? "").split(", ").map((s) => s.replace(/^DNS:/, "")).filter(Boolean).slice(0, 20) } : {}),
      };
      sock.end();
      resolve(info);
    });
    sock.on("timeout", () => sock.destroy(new Error("timed out")));
    sock.on("error", reject);
  });
}

export const resolveTxt = async (name: string): Promise<string[]> => (await dns.promises.resolveTxt(name)).map((parts) => parts.join(""));
export const resolveMx = async (name: string): Promise<string[]> => (await dns.promises.resolveMx(name)).map((m) => m.exchange);
