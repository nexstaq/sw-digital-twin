import { createHmac, createPublicKey, createVerify, generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { fetchSignals, GitHubError } from "./api";
import { appConfig, appJwt, tokenFor } from "./app";
import { nextPoke, poke } from "./bus";
import { isPublicRepo } from "./signals";
import { repoOfEvent, verifySignature } from "./webhook";

const sign = (secret: string, body: string) => `sha256=${createHmac("sha256", secret).update(body).digest("hex")}`;

describe("webhook", () => {
  it("accepts a correct signature and rejects everything else", () => {
    const body = '{"a":1}';
    expect(verifySignature("s3cret", body, sign("s3cret", body))).toBe(true);
    expect(verifySignature("s3cret", body, sign("other", body))).toBe(false);
    expect(verifySignature("s3cret", body + " ", sign("s3cret", body))).toBe(false);
    expect(verifySignature("s3cret", body, null)).toBe(false);
    expect(verifySignature("s3cret", body, "sha256=zz")).toBe(false);
    expect(verifySignature("s3cret", body, "sha1=abc")).toBe(false);
    expect(verifySignature("", body, sign("", body))).toBe(false);
  });

  it("maps handled events to a lowercased repo and ignores the rest", () => {
    const p = { repository: { full_name: "Acme/Shop" } };
    for (const e of ["workflow_run", "deployment_status", "check_run", "push"]) expect(repoOfEvent(e, p)).toBe("acme/shop");
    expect(repoOfEvent("star", p)).toBeNull();
    expect(repoOfEvent("push", {})).toBeNull();
    expect(repoOfEvent("push", { repository: { full_name: "../etc/passwd" } })).toBeNull();
    expect(repoOfEvent(null, p)).toBeNull();
  });
});

describe("bus", () => {
  it("wakes only listeners of that repo, and releases on abort", async () => {
    const a = new AbortController();
    const woke = vi.fn();
    const p = nextPoke("Acme/Shop", a.signal).then(woke);
    poke("other/repo");
    await Promise.resolve();
    expect(woke).not.toHaveBeenCalled();
    poke("acme/shop");
    await p;
    expect(woke).toHaveBeenCalledOnce();
    const b = new AbortController();
    const q = nextPoke("x/y", b.signal);
    b.abort();
    await q;
  });
});

describe("GitHub App auth", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });

  it("signs a verifiable RS256 JWT that expires within 10 minutes", () => {
    const jwt = appJwt("123", privateKey, 1_000_000);
    const [h, b, s] = jwt.split(".");
    expect(JSON.parse(Buffer.from(h, "base64url").toString())).toEqual({ alg: "RS256", typ: "JWT" });
    const body = JSON.parse(Buffer.from(b, "base64url").toString());
    expect(body.iss).toBe("123");
    expect(body.exp - body.iat).toBeLessThanOrEqual(600);
    expect(createVerify("RSA-SHA256").update(`${h}.${b}`).verify(createPublicKey(publicKey), Buffer.from(s, "base64url"))).toBe(true);
  });

  it("reads escaped newlines in the key from env", () => {
    expect(appConfig({ GITHUB_APP_ID: "1", GITHUB_APP_PRIVATE_KEY: "a\\nb" } as unknown as NodeJS.ProcessEnv)?.privateKey).toBe("a\nb");
    expect(appConfig({} as NodeJS.ProcessEnv)).toBeNull();
  });

  it("mints an installation token, caches it, and falls back to GITHUB_TOKEN when the app is not installed", async () => {
    const env = { GITHUB_APP_ID: "1", GITHUB_APP_PRIVATE_KEY: privateKey, GITHUB_TOKEN: "pat" } as unknown as NodeJS.ProcessEnv;
    const calls: string[] = [];
    const f = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const u = String(url); calls.push(`${init?.method ?? "GET"} ${u}`);
      if (u.endsWith("/repos/a/b/installation")) return Response.json({ id: 77 });
      if (u.endsWith("/app/installations/77/access_tokens")) return Response.json({ token: "inst-token", expires_at: new Date(Date.now() + 3_600_000).toISOString() });
      return new Response("nope", { status: 404 });
    }) as unknown as typeof fetch;
    expect(await tokenFor("a/b", { fetch: f, env })).toBe("inst-token");
    expect(await tokenFor("a/b", { fetch: f, env })).toBe("inst-token");
    expect(calls).toHaveLength(2); // second call served from cache
    expect(await tokenFor("not/installed", { fetch: f, env })).toBe("pat");
    expect(await tokenFor("x/y", { env: {} as NodeJS.ProcessEnv })).toBeUndefined();
  });
});

const J = (o: unknown, init?: ResponseInit) => Response.json(o, init);
function mockGitHub(over: Record<string, () => Response> = {}) {
  const routes: Record<string, () => Response> = {
    "/repos/a/b": () => J({ default_branch: "main" }),
    "/repos/a/b/actions/runs": () => J({ workflow_runs: [
      { id: 2, path: ".github/workflows/ci.yml", name: "CI", head_branch: "main", head_sha: "abc1234", event: "push", status: "completed", conclusion: "failure", run_attempt: 1, created_at: "2026-10-29T11:00:00Z", html_url: "https://github.com/a/b/actions/runs/2" },
      { id: 1, path: ".github/workflows/ci.yml", name: "CI", head_branch: "main", head_sha: "old", event: "push", status: "completed", conclusion: "success", run_attempt: 1, created_at: "2026-10-29T10:00:00Z", html_url: "https://github.com/a/b/actions/runs/1" },
    ] }),
    "/repos/a/b/actions/runs/2/jobs": () => J({ jobs: [{ name: "test", status: "completed", conclusion: "failure", html_url: "https://github.com/a/b/job/5", steps: [{ name: "Checkout", conclusion: "success" }, { name: "Run vitest", conclusion: "failure" }] }] }),
    "/repos/a/b/deployments": () => J([{ id: 9, environment: "production", sha: "abc1234", created_at: "2026-10-29T11:05:00Z", url: "x" }]),
    "/repos/a/b/deployments/9/statuses": () => J([{ state: "success", target_url: "https://prod.example" }]),
    ...over,
  };
  return vi.fn(async (url: string | URL | Request) => {
    const path = new URL(String(url)).pathname;
    const r = routes[path];
    return r ? r() : new Response("{}", { status: 404 });
  }) as unknown as typeof fetch;
}

describe("fetchSignals", () => {
  it("normalises runs, names the failing step, and reads deploy status", async () => {
    const s = await fetchSignals("a/b", { fetch: mockGitHub() });
    expect(s.defaultBranch).toBe("main");
    expect(s.runs).toHaveLength(2);
    expect(s.runs[0].jobs?.[0]).toMatchObject({ name: "test", failedStep: "Run vitest", url: "https://github.com/a/b/job/5" });
    expect(s.runs[1].jobs).toBeUndefined(); // only the latest finished run per workflow is opened
    expect(s.deploys[0]).toMatchObject({ environment: "production", state: "success", url: "https://prod.example" });
  });

  it("tolerates repos with no deployments API data and failing job lookups", async () => {
    const s = await fetchSignals("a/b", { fetch: mockGitHub({ "/repos/a/b/deployments": () => new Response("{}", { status: 404 }), "/repos/a/b/actions/runs/2/jobs": () => new Response("{}", { status: 500 }) }) });
    expect(s.deploys).toEqual([]);
    expect(s.runs[0].jobs).toBeUndefined();
  });

  it("raises a fatal error for missing repos and a retryable one for rate limits", async () => {
    await expect(fetchSignals("a/b", { fetch: mockGitHub({ "/repos/a/b": () => new Response("{}", { status: 404 }) }) })).rejects.toMatchObject({ status: 404, fatal: true });
    const limited = () => new Response("{}", { status: 403, headers: { "x-ratelimit-remaining": "0", "x-ratelimit-reset": "2000000000" } });
    const err = await fetchSignals("a/b", { fetch: mockGitHub({ "/repos/a/b": limited }) }).catch((e) => e);
    expect(err).toBeInstanceOf(GitHubError);
    expect(err).toMatchObject({ status: 429, fatal: false, retryAt: 2_000_000_000_000 });
  });

  it("sends the token when given and none otherwise", async () => {
    const f = mockGitHub();
    await fetchSignals("a/b", { fetch: f, token: "tok" });
    expect((vi.mocked(f).mock.calls[0][1] as RequestInit).headers).toMatchObject({ authorization: "Bearer tok" });
    const g = mockGitHub();
    await fetchSignals("a/b", { fetch: g });
    expect((vi.mocked(g).mock.calls[0][1] as RequestInit).headers).not.toHaveProperty("authorization");
  });
});

describe("isPublicRepo", () => {
  it("never sends credentials, so tokens cannot expose private repos to anonymous viewers", async () => {
    const f = vi.fn(async () => new Response("{}", { status: 404 })) as unknown as typeof fetch;
    process.env.GITHUB_TOKEN = "pat";
    expect(await isPublicRepo("priv/ate", f)).toBe(false);
    expect((vi.mocked(f).mock.calls[0] as unknown[])[1]).not.toHaveProperty("headers.authorization");
    delete process.env.GITHUB_TOKEN;
    expect(await isPublicRepo("pub/lic", mockGitHubPublic())).toBe(true);
  });
});
function mockGitHubPublic() { return vi.fn(async () => Response.json({ default_branch: "main" })) as unknown as typeof fetch; }
