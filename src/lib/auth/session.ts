import { createCipheriv, createDecipheriv, createHash, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Stateless sessions: the whole session (including the user's GitHub token) is sealed with AES-256-GCM into one httpOnly
 * cookie, so there is no session table. The token never reaches page JavaScript. Rotate SESSION_SECRET to sign everyone out.
 */
export interface Session {
  id: number;
  login: string;
  avatar?: string;
  /** GitHub user-to-server access token */
  token: string;
  refresh?: string;
  /** access token expiry, epoch ms */
  tokenExp: number;
  /** session expiry, epoch ms */
  exp: number;
}

export const SESSION_COOKIE = "twin_session";
export const OAUTH_COOKIE = "twin_oauth";
export const SESSION_TTL_MS = 30 * 24 * 3_600_000;

const key = (secret: string) => createHash("sha256").update(`twin.session.v1:${secret}`).digest();

export function secretOk(secret: string | undefined): secret is string {
  return !!secret && secret.length >= 32;
}

export function seal(value: unknown, secret: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key(secret), iv);
  const body = Buffer.concat([c.update(JSON.stringify(value), "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), body]).toString("base64url");
}

export function open<T>(sealed: string | undefined, secret: string): T | null {
  if (!sealed) return null;
  try {
    const raw = Buffer.from(sealed, "base64url");
    if (raw.length < 29) return null;
    const d = createDecipheriv("aes-256-gcm", key(secret), raw.subarray(0, 12));
    d.setAuthTag(raw.subarray(12, 28));
    return JSON.parse(Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString("utf8")) as T;
  } catch { return null; } // tampered, wrong secret, or garbage: all the same to the caller
}

export function readSession(sealed: string | undefined, secret: string, now = Date.now()): Session | null {
  const s = open<Session>(sealed, secret);
  return s && typeof s.token === "string" && typeof s.login === "string" && s.exp > now ? s : null;
}

export function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of (header ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

export function setCookie(name: string, value: string, o: { maxAgeSec: number; secure: boolean; path?: string }): string {
  return `${name}=${value}; Path=${o.path ?? "/"}; HttpOnly; SameSite=Lax; Max-Age=${o.maxAgeSec}${o.secure ? "; Secure" : ""}`;
}
export const clearCookie = (name: string, secure: boolean) => setCookie(name, "", { maxAgeSec: 0, secure });

export const safeEqual = (a: string, b: string) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

/** Only same-site relative paths may be used as a post-login destination (no open redirects). */
export function safeReturnTo(v: string | null | undefined): string {
  return v && /^\/(?![/\\])[\w\-./?=&%:,~]*$/.test(v) ? v : "/repos";
}
