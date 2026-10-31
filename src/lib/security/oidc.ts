import { createPublicKey, verify } from "node:crypto";

/** GitHub Actions can mint a short-lived signed token that proves which repository's workflow is running. */
const issuer = () => (process.env.GITHUB_ACTIONS_OIDC_ISSUER || "https://token.actions.githubusercontent.com").replace(/\/$/, "");

export interface ActionsClaims { repository: string; sha?: string; ref?: string; workflow?: string; run_id?: string; event_name?: string; actor?: string; repository_owner?: string }
export type OidcResult = { ok: true; claims: ActionsClaims } | { ok: false; reason: string };

interface Jwk { kty?: string; kid?: string; n?: string; e?: string; alg?: string; use?: string }
const cache = new Map<string, { at: number; keys: Jwk[] }>();
const TTL_MS = 10 * 60_000;
const REFETCH_MIN_MS = 30_000; // a token with an unknown key id cannot make us hammer GitHub
const LEEWAY_S = 30;
export const resetOidcCache = () => cache.clear();

async function keysFor(f: typeof fetch, now: number, force: boolean): Promise<Jwk[] | null> {
  const iss = issuer();
  const hit = cache.get(iss);
  if (hit && now - hit.at < (force ? REFETCH_MIN_MS : TTL_MS)) return hit.keys;
  try {
    const res = await f(`${iss}/.well-known/jwks`, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(8000) });
    if (!res.ok) return hit?.keys ?? null;
    const { keys } = (await res.json()) as { keys?: Jwk[] };
    if (!Array.isArray(keys)) return hit?.keys ?? null;
    cache.set(iss, { at: now, keys });
    return keys;
  } catch { return hit?.keys ?? null; }
}

const b64 = (s: string) => Buffer.from(s, "base64url");
const json = (s: string): Record<string, unknown> | null => { try { const v = JSON.parse(b64(s).toString("utf8")); return v && typeof v === "object" && !Array.isArray(v) ? v : null; } catch { return null; } };

/**
 * Verifies a GitHub Actions OIDC token: RS256 signature against GitHub's published keys, issuer, audience (this service), expiry,
 * and a well-formed `repository` claim. The algorithm is pinned: `none` and HS256 "algorithm confusion" tokens are refused.
 * What it proves: some workflow in `claims.repository` is running right now. Nothing else, so callers must compare the repo.
 */
export async function verifyActionsToken(token: string, o: { audience: string; fetch?: typeof fetch; now?: number }): Promise<OidcResult> {
  const now = o.now ?? Date.now();
  const f = o.fetch ?? fetch;
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]+$/.test(p))) return { ok: false, reason: "malformed token" };
  const header = json(parts[0]);
  if (!header || header.alg !== "RS256" || typeof header.kid !== "string") return { ok: false, reason: "unsupported algorithm" };

  let keys = await keysFor(f, now, false);
  if (!keys) return { ok: false, reason: "could not fetch GitHub's signing keys" };
  let jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) { keys = (await keysFor(f, now + REFETCH_MIN_MS, true)) ?? keys; jwk = keys.find((k) => k.kid === header.kid); } // keys rotate: one fresh look
  if (!jwk || jwk.kty !== "RSA" || !jwk.n || !jwk.e) return { ok: false, reason: "unknown signing key" };

  try {
    const key = createPublicKey({ key: { kty: "RSA", n: jwk.n, e: jwk.e }, format: "jwk" });
    if (!verify("RSA-SHA256", Buffer.from(`${parts[0]}.${parts[1]}`), key, b64(parts[2]))) return { ok: false, reason: "bad signature" };
  } catch { return { ok: false, reason: "bad signature" }; }

  const c = json(parts[1]);
  if (!c) return { ok: false, reason: "malformed token" };
  const nowS = Math.floor(now / 1000);
  if (c.iss !== issuer()) return { ok: false, reason: "wrong issuer" };
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!aud.includes(o.audience)) return { ok: false, reason: "wrong audience" };
  if (typeof c.exp !== "number" || c.exp + LEEWAY_S < nowS) return { ok: false, reason: "expired" };
  if (typeof c.nbf === "number" && c.nbf - LEEWAY_S > nowS) return { ok: false, reason: "not valid yet" };
  if (typeof c.repository !== "string" || !/^[\w.-]+\/[\w.-]+$/.test(c.repository)) return { ok: false, reason: "no repository claim" };

  const s = (v: unknown) => (typeof v === "string" ? v.slice(0, 200) : undefined);
  return { ok: true, claims: { repository: c.repository, sha: s(c.sha), ref: s(c.ref), workflow: s(c.workflow), run_id: s(c.run_id), event_name: s(c.event_name), actor: s(c.actor), repository_owner: s(c.repository_owner) } };
}
