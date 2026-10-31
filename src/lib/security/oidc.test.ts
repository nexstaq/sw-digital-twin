import { createHmac, createSign, generateKeyPairSync, type KeyObject } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { resetOidcCache, verifyActionsToken } from "./oidc";

const ISS = "https://token.actions.githubusercontent.com";
const AUD = "https://app.example.com";
const NOW = 1_800_000_000_000;
const nowS = NOW / 1000;
const b64 = (o: unknown) => Buffer.from(typeof o === "string" ? o : JSON.stringify(o)).toString("base64url");

const mkKey = (kid: string) => { const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 }); const j = publicKey.export({ format: "jwk" }); return { kid, privateKey, jwk: { kty: "RSA", kid, n: j.n, e: j.e, alg: "RS256", use: "sig" } }; };
const A = mkKey("key-a"), B = mkKey("key-b");

const sign = (claims: Record<string, unknown>, k: { kid: string; privateKey: KeyObject }, header: Record<string, unknown> = {}) => {
  const head = b64({ alg: "RS256", typ: "JWT", kid: k.kid, ...header });
  const body = b64({ iss: ISS, aud: AUD, repository: "acme/shop", sha: "a".repeat(40), ref: "refs/heads/main", workflow: "Security scan", run_id: "42", event_name: "push", actor: "alice", exp: nowS + 300, nbf: nowS - 10, iat: nowS - 10, ...claims });
  const s = createSign("RSA-SHA256").update(`${head}.${body}`).sign(k.privateKey).toString("base64url");
  return `${head}.${body}.${s}`;
};
const jwks = (keys: { jwk: object }[]) => vi.fn(async () => Response.json({ keys: keys.map((k) => k.jwk) })) as unknown as typeof fetch;
const verify = (t: string, f = jwks([A]), extra: { now?: number } = {}) => verifyActionsToken(t, { audience: AUD, fetch: f, now: NOW, ...extra });

beforeEach(() => resetOidcCache());

describe("verifyActionsToken: what it accepts", () => {
  it("a valid token yields the claims that identify the workflow run", async () => {
    const r = await verify(sign({}, A));
    expect(r).toEqual({ ok: true, claims: { repository: "acme/shop", sha: "a".repeat(40), ref: "refs/heads/main", workflow: "Security scan", run_id: "42", event_name: "push", actor: "alice", repository_owner: undefined } });
  });
  it("accepts an audience list that includes ours", async () => { expect((await verify(sign({ aud: ["other", AUD] }, A))).ok).toBe(true); });
  it("tolerates small clock skew either way", async () => {
    expect((await verify(sign({ exp: nowS - 10 }, A))).ok).toBe(true); // expired 10s ago, inside the 30s leeway
    expect((await verify(sign({ nbf: nowS + 10 }, A))).ok).toBe(true);
  });
});

describe("verifyActionsToken: attacks it must refuse", () => {
  const reason = async (t: string, f?: typeof fetch) => { const r = await verify(t, f); return r.ok ? "ACCEPTED" : r.reason; };

  it("a token for a different audience (minted for some other service)", async () => { expect(await reason(sign({ aud: "https://evil.example" }, A))).toBe("wrong audience"); });
  it("an expired token, and one that is not valid yet", async () => {
    expect(await reason(sign({ exp: nowS - 120 }, A))).toBe("expired");
    expect(await reason(sign({ nbf: nowS + 120 }, A))).toBe("not valid yet");
  });
  it("a token from another issuer", async () => { expect(await reason(sign({ iss: "https://evil.example" }, A))).toBe("wrong issuer"); });
  it("alg:none, with or without a signature", async () => {
    const body = b64({ iss: ISS, aud: AUD, repository: "acme/shop", exp: nowS + 300 });
    expect(await reason(`${b64({ alg: "none", kid: "key-a" })}.${body}.`)).toBe("malformed token");
    expect(await reason(`${b64({ alg: "none", kid: "key-a" })}.${body}.AAAA`)).toBe("unsupported algorithm");
  });
  it("HS256 'algorithm confusion': signed with GitHub's PUBLIC key as an HMAC secret", async () => {
    const head = b64({ alg: "HS256", typ: "JWT", kid: "key-a" });
    const body = b64({ iss: ISS, aud: AUD, repository: "acme/shop", exp: nowS + 300 });
    const pub = JSON.stringify(A.jwk);
    const forged = `${head}.${body}.${createHmac("sha256", pub).update(`${head}.${body}`).digest("base64url")}`;
    expect(await reason(forged)).toBe("unsupported algorithm");
  });
  it("a token signed by a key GitHub never published, claiming a published key id", async () => {
    expect(await reason(sign({}, { kid: "key-a", privateKey: B.privateKey }))).toBe("bad signature");
  });
  it("a tampered payload: the repository swapped after signing", async () => {
    const [h, , s] = sign({}, A).split(".");
    const forged = `${h}.${b64({ iss: ISS, aud: AUD, repository: "victim/secrets", exp: nowS + 300 })}.${s}`;
    expect(await reason(forged)).toBe("bad signature");
  });
  it("a missing or malformed repository claim", async () => {
    expect(await reason(sign({ repository: undefined }, A))).toBe("no repository claim");
    expect(await reason(sign({ repository: "../../etc" }, A))).toBe("no repository claim");
    expect(await reason(sign({ repository: "a/b/c" }, A))).toBe("no repository claim");
  });
  it("junk", async () => {
    for (const junk of ["", "a.b", "a.b.c.d", "not a token", "a.b.!!", `${b64("x")}.${b64("y")}.${b64("z")}`]) expect(await reason(junk), junk).not.toBe("ACCEPTED");
  });
  it("an unknown key id is refused, after one fresh look at the keys (they rotate)", async () => {
    const f = jwks([A]);
    expect(await reason(sign({}, B), f)).toBe("unknown signing key");
    expect((f as unknown as ReturnType<typeof vi.fn>).mock.calls.length).toBe(2); // cached fetch, then one refetch
  });
});

describe("verifyActionsToken: GitHub's keys", () => {
  it("picks up a newly rotated key", async () => {
    let published = [A];
    const f = vi.fn(async () => Response.json({ keys: published.map((k) => k.jwk) })) as unknown as typeof fetch;
    expect((await verify(sign({}, A), f)).ok).toBe(true);
    published = [A, B];
    expect((await verifyActionsToken(sign({}, B), { audience: AUD, fetch: f, now: NOW + 40_000 })).ok).toBe(true); // 40s later: past the refetch floor
  });
  it("caches the keys, so many tokens cost one fetch", async () => {
    const f = jwks([A]);
    for (let i = 0; i < 5; i++) await verify(sign({ run_id: String(i) }, A), f);
    expect((f as unknown as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(1);
  });
  it("an unknown key id cannot make us hammer GitHub: refetches are rate limited", async () => {
    const f = jwks([A]);
    for (let i = 0; i < 6; i++) await verify(sign({}, B), f);
    expect((f as unknown as ReturnType<typeof vi.fn>).mock.calls.length).toBeLessThanOrEqual(2);
  });
  it("fails closed when the keys cannot be fetched", async () => {
    const down = (async () => new Response("no", { status: 503 })) as unknown as typeof fetch;
    const r = await verify(sign({}, A), down);
    expect(r).toEqual({ ok: false, reason: "could not fetch GitHub's signing keys" });
    const thrown = (async () => { throw new Error("offline"); }) as unknown as typeof fetch;
    expect((await verify(sign({}, A), thrown)).ok).toBe(false);
  });
  it("keeps working from cached keys through a short GitHub outage", async () => {
    expect((await verify(sign({}, A), jwks([A]))).ok).toBe(true);
    const down = (async () => new Response("no", { status: 503 })) as unknown as typeof fetch;
    expect((await verifyActionsToken(sign({}, A), { audience: AUD, fetch: down, now: NOW + 5000 })).ok).toBe(true);
  });
});
