process.env.TWIN_PERSIST = "memory"; // never write .data/ from tests
import { describe, expect, it, vi } from "vitest";
import { fixtureGraph } from "@/lib/graph/fixture";
import { memoryPersist } from "@/lib/persist/memory";
import { collect, connectorsEnabledFor } from "./collect";
import { proposeMappings } from "./match";
import { bucketsFromTraces, TracesBody } from "./otlp";
import { otlpAuthorized } from "./otlp-config";
import { sentry } from "./sentry";
import { vercel } from "./vercel";
import type { ConnectorCtx } from "./types";

const NOW = Date.parse("2026-10-29T12:00:00Z");
const env = (o: Record<string, string>) => o as unknown as NodeJS.ProcessEnv;
const ctx = (e: NodeJS.ProcessEnv, f: typeof fetch): ConnectorCtx => ({ env: e, fetch: f, now: NOW });
const json = (o: unknown) => Response.json(o);

function sentryMock() {
  const hours = Array.from({ length: 4 }, (_, i) => new Date(NOW - (3 - i) * 3_600_000).toISOString());
  return vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
    const u = String(url);
    expect((init?.headers as Record<string, string>).authorization).toBe("Bearer tok");
    if (u.includes("/organizations/acme/projects/")) return json([{ id: "11", slug: "payments", name: "Payments" }, { id: "12", slug: "web" }]);
    if (u.includes("/stats_v2/")) return json({ intervals: hours, groups: [
      { by: { project: 11 }, series: { "sum(quantity)": [60, 60, 60, 2400] } },
      { by: { project: 12 }, series: { "sum(quantity)": [0, 0, 0, 0] } },
    ] });
    if (u.includes("/projects/acme/payments/issues/")) return json([{ title: "TimeoutError: charge", count: "2312", permalink: "https://sentry.io/i/9" }]);
    return new Response("{}", { status: 404 });
  }) as unknown as typeof fetch;
}

describe("sentry connector", () => {
  const e = env({ SENTRY_AUTH_TOKEN: "tok", SENTRY_ORG: "acme" });
  it("needs token and org", () => { expect(sentry.configured(env({}))).toBe(false); expect(sentry.configured(e)).toBe(true); });
  it("discovers projects", async () => {
    expect((await sentry.discover(ctx(e, sentryMock()))).map((t) => t.key)).toEqual(["payments", "web"]);
  });
  it("turns hourly counts into errors/min per project slug and names the top issue on the newest bucket", async () => {
    const { buckets } = await sentry.poll(ctx(e, sentryMock()));
    const pay = buckets!.filter((b) => b.key === "payments");
    expect(pay.map((b) => b.errors)).toEqual([1, 1, 1, 40]);
    expect(pay.at(-1)!.top).toEqual([{ title: "TimeoutError: charge", count: 2312, url: "https://sentry.io/i/9" }]);
    expect(buckets!.filter((b) => b.key === "web").every((b) => !b.top)).toBe(true);
  });
  it("reports a rejected token without leaking it", async () => {
    const secret = env({ SENTRY_AUTH_TOKEN: "sntrys_SECRET123", SENTRY_ORG: "acme" });
    const f = vi.fn(async () => new Response("no", { status: 403 })) as unknown as typeof fetch;
    const err = await sentry.discover(ctx(secret, f)).catch((x: Error) => x);
    expect((err as Error).message).toMatch(/rejected/);
    expect((err as Error).message).not.toContain("SECRET123");
  });
});

describe("vercel connector", () => {
  const e = env({ VERCEL_TOKEN: "tok", VERCEL_PROJECT_ID: "prj_1" });
  it("maps deployment states and targets", async () => {
    const f = vi.fn(async () => json({ deployments: [
      { uid: "dpl_1", created: NOW - 60_000, target: "production", state: "ERROR", meta: { githubCommitSha: "abc1234" }, inspectorUrl: "https://vercel.com/x/1" },
      { uid: "dpl_2", created: NOW - 600_000, target: null, readyState: "READY", url: "x.vercel.app" },
      { uid: "dpl_3", created: NOW - 5000, target: "production", state: "BUILDING" },
    ] })) as unknown as typeof fetch;
    const { deploys } = await vercel.poll(ctx(e, f));
    expect(deploys!.map((d) => [d.environment, d.state])).toEqual([["production", "failure"], ["preview", "success"], ["production", "in_progress"]]);
    expect(deploys![0]).toMatchObject({ sha: "abc1234", url: "https://vercel.com/x/1" });
    expect(deploys![1].url).toBe("https://x.vercel.app");
  });
});

describe("otlp ingest", () => {
  const span = (startMs: number, ms: number, o: Record<string, unknown> = {}) => ({ startTimeUnixNano: `${startMs}000000`, endTimeUnixNano: `${startMs + ms}000000`, kind: 2, ...o });
  const body = (spans: unknown[], name = "payments") => TracesBody.parse({ resourceSpans: [{ resource: { attributes: [{ key: "service.name", value: { stringValue: name } }] }, scopeSpans: [{ spans }] }] });
  const T0 = Math.floor(NOW / 300_000) * 300_000;

  it("rolls spans into 5-minute buckets: rates per minute and p95", () => {
    const spans = Array.from({ length: 100 }, (_, i) => span(T0 + i * 100, i + 1, i < 10 ? { status: { code: 2 } } : {}));
    const [b] = bucketsFromTraces(body(spans));
    expect(b).toMatchObject({ source: "otlp", key: "payments", ts: T0, requests: 20, errors: 2 });
    expect(b.p95Ms).toBe(96);
  });
  it("counts entry points only, not internal calls", () => {
    const spans = [span(T0, 5), span(T0, 5, { kind: 1 }), span(T0, 5, { kind: 3 }), span(T0, 5, { kind: undefined }), span(T0, 5, { kind: undefined, parentSpanId: "abc" })];
    expect(bucketsFromTraces(body(spans))[0].requests).toBe(2 / 5);
  });
  it("splits across bucket boundaries and skips services with no name or bad spans", () => {
    const b = bucketsFromTraces(body([span(T0, 5), span(T0 + 300_000, 5), span(T0, -1)]));
    expect(b.map((x) => x.ts)).toEqual([T0, T0 + 300_000]);
    expect(bucketsFromTraces(TracesBody.parse({ resourceSpans: [{ scopeSpans: [{ spans: [span(T0, 5)] }] }] }))).toEqual([]);
  });
  it("authorises only the exact key", () => {
    const e = env({ OTLP_INGEST_KEY: "s3cret" });
    expect(otlpAuthorized("Bearer s3cret", e)).toBe(true);
    for (const h of ["Bearer s3cre", "Bearer s3cret!", "s3cret", null]) expect(otlpAuthorized(h, e)).toBe(false);
    expect(otlpAuthorized("Bearer x", env({}))).toBe(false);
  });
});

describe("matching signals to nodes", () => {
  const g = fixtureGraph;
  const t = (key: string, name = key) => ({ source: "sentry", key, name });
  it("auto-matches by name and rates confidence", () => {
    const [pay, nothing, fuzzy] = [proposeMappings(g, [t("payments")]), proposeMappings(g, [t("zzzz")]), proposeMappings(g, [t("api-gateway-prod", "API gateway")])];
    expect(pay[0]).toMatchObject({ id: "sentry:payments", nodeId: "pay", confirmed: false });
    expect(pay[0].confidence).not.toBe("low");
    expect(nothing).toEqual([]);
    expect(fuzzy[0].nodeId).toBe("api");
  });
  it("never proposes a file, endpoint or job", () => {
    const p = proposeMappings(g, [t("charge.ts"), t("Run")]);
    for (const x of p) expect(["file", "endpoint", "job"]).not.toContain(g.nodes.find((n) => n.id === x.nodeId)!.kind);
  });
  it("keeps what the user already confirmed, and drops it if the node is gone", () => {
    const p = proposeMappings(g, [t("payments")], { "sentry:payments": "api" });
    expect(p[0]).toMatchObject({ nodeId: "api", confirmed: true });
    expect(proposeMappings(g, [t("payments")], { "sentry:payments": "gone" })[0]).toMatchObject({ nodeId: "pay", confirmed: false });
  });
});

describe("collect caching", () => {
  it("caches what it pulls but never serves stale pushed telemetry", async () => {
    const e = env({ CONNECTOR_REPOS: "cache/me", OTLP_INGEST_KEY: "k", SENTRY_AUTH_TOKEN: "tok", SENTRY_ORG: "acme" });
    const f = sentryMock();
    const first = await collect("cache/me", { env: e, fetch: f, now: NOW });
    expect(first.targets.some((t) => t.source === "otlp")).toBe(false);
    const { persist } = await import("@/lib/persist");
    await persist().putBuckets("cache/me", [{ source: "otlp", key: "backend", ts: Date.now() - 60_000, errors: 1, requests: 10 }]);
    const calls = vi.mocked(f).mock.calls.length;
    const second = await collect("cache/me", { env: e, fetch: f, now: NOW + 5_000 });
    expect(vi.mocked(f).mock.calls.length).toBe(calls); // Sentry was not asked again
    expect(second.targets.some((t) => t.source === "otlp" && t.key === "backend")).toBe(true); // but the new traces are visible
  });
});

describe("collect (gated)", () => {
  it("serves nothing unless the repo is allow-listed", async () => {
    const f = vi.fn() as unknown as typeof fetch;
    const c = await collect("acme/shop", { env: env({ SENTRY_AUTH_TOKEN: "tok", SENTRY_ORG: "acme" }), fetch: f, store: memoryPersist() });
    expect(f).not.toHaveBeenCalled();
    expect(c.runtime).toEqual([]);
    expect(c.status.every((s) => s.state === "off")).toBe(true);
    expect(connectorsEnabledFor("Acme/Shop", env({ CONNECTOR_REPOS: "x/y, acme/shop" }))).toBe(true);
  });
  it("combines pulled and pushed signals and isolates a failing connector", async () => {
    const store = memoryPersist();
    await store.putBuckets("acme/shop", [{ source: "otlp", key: "api", ts: NOW - 300_000, errors: 1, requests: 50, p95Ms: 40 }]);
    const e = env({ CONNECTOR_REPOS: "acme/shop", SENTRY_AUTH_TOKEN: "tok", SENTRY_ORG: "acme", VERCEL_TOKEN: "v", VERCEL_PROJECT_ID: "p", OTLP_INGEST_KEY: "k" });
    const f = vi.fn(async (url: string | URL | Request, init?: RequestInit) => String(url).includes("vercel") ? new Response("x", { status: 500 }) : (sentryMock() as unknown as (u: unknown, i: unknown) => Promise<Response>)(url, init)) as unknown as typeof fetch;
    const c = await collect("acme/shop", { env: e, fetch: f, store, now: NOW });
    expect(c.status.find((s) => s.id === "sentry")!.state).toBe("ok");
    expect(c.status.find((s) => s.id === "vercel")!.state).toBe("error");
    expect(c.status.find((s) => s.id === "otlp")!.state).toBe("ok");
    expect(new Set(c.runtime.map((b) => b.source))).toEqual(new Set(["sentry", "otlp"]));
    expect(c.targets.map((t) => `${t.source}:${t.key}`).sort()).toEqual(["otlp:api", "sentry:payments", "sentry:web"]);
  });
});
