import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { authorizeUrl, exchangeCode, fetchUser, listRepos, refreshTokens, repoAccess } from "./github";
import { open, parseCookies, readSession, safeReturnTo, seal, setCookie, type Session } from "./session";
import { authorizeRepo, viewerOf } from "./viewer";
import { tokenFor } from "@/lib/github/app";

const SECRET = "x".repeat(40);
const NOW = 1_800_000_000_000;
const session = (o: Partial<Session> = {}): Session => ({ id: 1, login: "octo", token: "gho_user", refresh: "ghr_r", tokenExp: NOW + 3_600_000, exp: NOW + 86_400_000, ...o });
const req = (cookie?: string) => new Request("http://x/api", { headers: cookie ? { cookie } : {} });
const cookieFor = (s: Session) => `twin_session=${seal(s, SECRET)}`;
const env = { SESSION_SECRET: SECRET, GITHUB_APP_CLIENT_ID: "cid", GITHUB_APP_CLIENT_SECRET: "csecret" } as unknown as NodeJS.ProcessEnv;

describe("sealed sessions", () => {
  it("round-trips and the token never appears in the cookie", () => {
    const c = seal(session(), SECRET);
    expect(c).not.toContain("gho_user");
    expect(Buffer.from(c, "base64url").toString("latin1")).not.toContain("gho_user");
    expect(open<Session>(c, SECRET)!.login).toBe("octo");
  });
  it("rejects tampering, a wrong secret and garbage", () => {
    const c = seal(session(), SECRET);
    const flipped = c.slice(0, -3) + (c.endsWith("AAA") ? "BBB" : "AAA");
    expect(open(flipped, SECRET)).toBeNull();
    expect(open(c, "y".repeat(40))).toBeNull();
    expect(open("not-a-cookie", SECRET)).toBeNull();
    expect(open(undefined, SECRET)).toBeNull();
  });
  it("two seals of the same session differ (fresh IV)", () => expect(seal(session(), SECRET)).not.toBe(seal(session(), SECRET)));
  it("expired sessions are signed out", () => {
    expect(readSession(seal(session({ exp: NOW - 1 }), SECRET), SECRET, NOW)).toBeNull();
    expect(readSession(seal(session(), SECRET), SECRET, NOW)).not.toBeNull();
  });
  it("cookies are httpOnly, SameSite=Lax, Secure when asked", () => {
    expect(setCookie("a", "b", { maxAgeSec: 5, secure: true })).toBe("a=b; Path=/; HttpOnly; SameSite=Lax; Max-Age=5; Secure");
    expect(setCookie("a", "b", { maxAgeSec: 5, secure: false })).not.toContain("Secure");
    expect(parseCookies("a=1; twin_session=abc=; b=2")).toMatchObject({ a: "1", twin_session: "abc=", b: "2" });
  });
  it("only allows same-site relative return paths", () => {
    expect(safeReturnTo("/repos")).toBe("/repos");
    expect(safeReturnTo("/scan?repo=a/b")).toBe("/scan?repo=a/b");
    for (const bad of ["//evil.com", "https://evil.com", "/\\evil.com", "javascript:alert(1)", "", null, undefined]) expect(safeReturnTo(bad), String(bad)).toBe("/repos");
  });
});

const json = (o: unknown, init?: ResponseInit) => Response.json(o, init);
describe("GitHub OAuth helpers", () => {
  const cfg = { clientId: "cid", clientSecret: "csecret" };
  it("builds the authorize URL with state and redirect", () => {
    const u = new URL(authorizeUrl("cid", "st4te", "http://app/cb"));
    expect(u.pathname).toBe("/login/oauth/authorize");
    expect(Object.fromEntries(u.searchParams)).toMatchObject({ client_id: "cid", state: "st4te", redirect_uri: "http://app/cb" });
  });
  it("exchanges a code for tokens with an absolute expiry, and surfaces GitHub's error", async () => {
    const f = vi.fn(async () => json({ access_token: "gho_1", refresh_token: "ghr_1", expires_in: 28800 })) as unknown as typeof fetch;
    expect(await exchangeCode(cfg, "code", "http://app/cb", f, NOW)).toEqual({ token: "gho_1", refresh: "ghr_1", tokenExp: NOW + 28_800_000 });
    const bad = vi.fn(async () => json({ error: "bad_verification_code", error_description: "The code passed is incorrect or expired." })) as unknown as typeof fetch;
    await expect(exchangeCode(cfg, "x", "u", bad)).rejects.toThrow(/incorrect or expired/);
  });
  it("refreshes tokens", async () => {
    const f = vi.fn(async (_u: unknown, init?: RequestInit) => { expect(String(init!.body)).toContain("grant_type=refresh_token"); return json({ access_token: "gho_2", refresh_token: "ghr_2", expires_in: 100 }); }) as unknown as typeof fetch;
    expect((await refreshTokens(cfg, "ghr_1", f, NOW)).token).toBe("gho_2");
  });
  it("maps repo permissions for THIS user's token, and treats 404 as no access", async () => {
    const f = (code: number, body: unknown) => vi.fn(async () => json(body, { status: code })) as unknown as typeof fetch;
    expect(await repoAccess("tok-aaaaaaaaaaaa1", "o/r1", f(200, { private: true, permissions: { pull: true, push: true } }), NOW)).toEqual({ read: true, push: true, private: true });
    expect(await repoAccess("tok-aaaaaaaaaaaa2", "o/r2", f(200, { private: false, permissions: { pull: true } }), NOW)).toEqual({ read: true, push: false, private: false });
    expect(await repoAccess("tok-aaaaaaaaaaaa3", "o/r3", f(404, {}), NOW)).toEqual({ read: false, push: false, private: true });
  });
  it("caches access checks briefly", async () => {
    const f = vi.fn(async () => json({ private: true, permissions: { pull: true } })) as unknown as typeof fetch;
    await repoAccess("tok-bbbbbbbbbbbb", "o/c", f, NOW); await repoAccess("tok-bbbbbbbbbbbb", "o/c", f, NOW + 1000);
    expect(f).toHaveBeenCalledTimes(1);
    await repoAccess("tok-bbbbbbbbbbbb", "o/c", f, NOW + 5 * 60_000);
    expect(f).toHaveBeenCalledTimes(2);
  });
  it("lists repos across installations, newest first, with write access flagged", async () => {
    const f = vi.fn(async (u: string | URL | Request) => {
      const p = String(u);
      if (p.includes("/user/installations?")) return json({ installations: [{ id: 1, account: { login: "acme" } }, { id: 2, account: { login: "me" } }] });
      if (p.includes("/installations/1/")) return json({ repositories: [{ full_name: "acme/api", private: true, pushed_at: "2026-01-02T00:00:00Z", permissions: { push: true } }] });
      return json({ repositories: [{ full_name: "me/site", private: false, pushed_at: "2026-02-01T00:00:00Z" }] });
    }) as unknown as typeof fetch;
    const r = await listRepos("tok", f);
    expect(r.map((x) => x.fullName)).toEqual(["me/site", "acme/api"]);
    expect(r[1]).toMatchObject({ private: true, canPush: true, owner: "acme" });
    expect(r[0].canPush).toBe(false);
  });
  it("fetchUser returns null for a rejected token", async () => {
    expect(await fetchUser("bad", vi.fn(async () => json({}, { status: 401 })) as unknown as typeof fetch)).toBeNull();
  });
});

describe("viewerOf", () => {
  it("is signed out without a valid secret, cookie or when expired", async () => {
    expect(await viewerOf(req(cookieFor(session())), { env: {} as NodeJS.ProcessEnv, now: NOW })).toBeNull();
    expect(await viewerOf(req(), { env, now: NOW })).toBeNull();
    expect(await viewerOf(req(cookieFor(session({ exp: NOW - 1 }))), { env, now: NOW })).toBeNull();
    expect(await viewerOf(req("twin_session=forged"), { env, now: NOW })).toBeNull();
  });
  it("returns the session without calling GitHub while the token is fresh", async () => {
    const f = vi.fn() as unknown as typeof fetch;
    const v = await viewerOf(req(cookieFor(session())), { env, fetch: f, now: NOW });
    expect(v!.session.login).toBe("octo");
    expect(v!.setCookie).toBeUndefined();
    expect(f).not.toHaveBeenCalled();
  });
  it("refreshes a token that is about to expire and hands back a new cookie", async () => {
    const f = vi.fn(async () => json({ access_token: "gho_new", refresh_token: "ghr_new", expires_in: 28800 })) as unknown as typeof fetch;
    const v = await viewerOf(req(cookieFor(session({ tokenExp: NOW + 60_000 }))), { env, fetch: f, now: NOW });
    expect(v!.session.token).toBe("gho_new");
    const sealed = v!.setCookie!.split(";")[0].split("=").slice(1).join("=");
    expect(open<Session>(sealed, SECRET)!.token).toBe("gho_new");
    expect(v!.setCookie).toMatch(/HttpOnly/);
  });
  it("signs out when the refresh fails (revoked)", async () => {
    const f = vi.fn(async () => json({ error: "bad_refresh_token" })) as unknown as typeof fetch;
    expect(await viewerOf(req(cookieFor(session({ tokenExp: NOW + 60_000 }))), { env, fetch: f, now: NOW })).toBeNull();
  });
});

describe("authorizeRepo: who may see what", () => {
  const signedIn = { viewer: async () => ({ session: session() }) };
  const anon = { viewer: async () => null };
  const priv = { isPublic: async () => false };
  const pub = { isPublic: async () => true };
  const app = { appToken: vi.fn(async (_r: string, o?: { installationOnly?: boolean }) => (o?.installationOnly ? "inst-token" : "shared-token")) };
  const yes = (push = false) => ({ access: async () => ({ read: true, push, private: true }) });
  const no = { access: async () => ({ read: false, push: false, private: true }) };
  const run = (deps: object, need?: "read" | "push") => authorizeRepo(req(), "o/r", { need, deps: deps as never });

  it("public repo: anyone may read", async () => expect(await run({ ...pub, ...anon, ...app })).toMatchObject({ ok: true, private: false }));
  it("private repo, signed out: 401, and the App token is never even requested", async () => {
    app.appToken.mockClear();
    expect(await run({ ...priv, ...anon, ...app })).toMatchObject({ ok: false, status: 401 });
    expect(app.appToken).not.toHaveBeenCalled();
  });
  it("private repo, signed in but GitHub says no access: 403, App token never requested", async () => {
    app.appToken.mockClear();
    expect(await run({ ...priv, ...signedIn, ...no, ...app })).toMatchObject({ ok: false, status: 403 });
    expect(app.appToken).not.toHaveBeenCalled();
  });
  it("private repo, access granted: reads with the installation token, never the shared PAT", async () => {
    app.appToken.mockClear();
    const r = await run({ ...priv, ...signedIn, ...yes(), ...app });
    expect(r).toMatchObject({ ok: true, private: true, token: "inst-token" });
    expect(app.appToken).toHaveBeenCalledWith("o/r", { installationOnly: true });
  });
  it("falls back to the user's own token when the App is not installed", async () => {
    const r = await run({ ...priv, ...signedIn, ...yes(), appToken: async () => undefined });
    expect(r).toMatchObject({ ok: true, token: "gho_user" });
  });
  it("writing needs push access, even on a public repo", async () => {
    expect(await run({ ...pub, ...anon, ...app }, "push")).toMatchObject({ ok: false, status: 401 });
    expect(await run({ ...pub, ...signedIn, ...yes(false), ...app }, "push")).toMatchObject({ ok: false, status: 403 });
    expect(await run({ ...pub, ...signedIn, ...yes(true), ...app }, "push")).toMatchObject({ ok: true });
  });
  it("a GitHub outage while checking access is a 502, not an accidental allow", async () => {
    expect(await run({ ...priv, ...signedIn, access: async () => { throw new Error("boom"); }, ...app })).toMatchObject({ ok: false, status: 502 });
  });
  it("a rate-limited public check is a 429, not a verdict", async () => {
    expect(await run({ isPublic: async () => { throw new Error("rate"); }, ...signedIn, ...yes(), ...app })).toMatchObject({ ok: false, status: 429 });
  });
});

describe("tokenFor installationOnly", () => {
  it("never returns the shared PAT for private repos", async () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
    const e = { GITHUB_APP_ID: "1", GITHUB_APP_PRIVATE_KEY: privateKey, GITHUB_TOKEN: "shared-pat" } as unknown as NodeJS.ProcessEnv;
    const f = vi.fn(async () => new Response("{}", { status: 404 })) as unknown as typeof fetch;
    expect(await tokenFor("not/installed", { fetch: f, env: e, installationOnly: true })).toBeUndefined();
    expect(await tokenFor("not/installed", { fetch: f, env: e })).toBe("shared-pat");
  });
});
