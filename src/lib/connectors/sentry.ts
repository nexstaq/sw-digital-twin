import { z } from "zod";
import type { RuntimeBucket } from "@/lib/health/signals";
import { getJson } from "./http";
import type { Connector, Target } from "./types";

/**
 * Sentry via its REST API: error volume per project (hourly, Sentry's finest stats resolution) plus the top unresolved
 * issues, linked, so an unhealthy node says WHICH exception.
 * NOTE: written against Sentry's documented response shapes and tested with a mock server; not yet run against a live org.
 */
const Projects = z.array(z.object({ id: z.union([z.string(), z.number()]).transform(String), slug: z.string(), name: z.string().optional() }));
const Stats = z.object({
  intervals: z.array(z.string()),
  groups: z.array(z.object({ by: z.object({ project: z.union([z.string(), z.number()]).transform(String) }), series: z.record(z.string(), z.array(z.number())) })),
});
const Issues = z.array(z.object({ title: z.string(), count: z.union([z.string(), z.number()]).transform(Number), permalink: z.string() }));

const base = (env: NodeJS.ProcessEnv) => (env.SENTRY_BASE_URL ?? "https://sentry.io").replace(/\/$/, "");

export const sentry: Connector = {
  id: "sentry", label: "Sentry", needs: ["SENTRY_AUTH_TOKEN", "SENTRY_ORG"],
  configured: (env) => !!(env.SENTRY_AUTH_TOKEN && env.SENTRY_ORG),

  async discover(ctx) {
    const { SENTRY_AUTH_TOKEN: token = "", SENTRY_ORG: org = "" } = ctx.env;
    const ps = Projects.parse(await getJson(ctx, `${base(ctx.env)}/api/0/organizations/${encodeURIComponent(org)}/projects/`, token));
    return ps.map((p): Target => ({ source: "sentry", key: p.slug, name: p.name ?? p.slug, url: `${base(ctx.env)}/organizations/${org}/projects/${p.slug}/` }));
  },

  async poll(ctx) {
    const { SENTRY_AUTH_TOKEN: token = "", SENTRY_ORG: org = "" } = ctx.env;
    const o = encodeURIComponent(org);
    const projects = Projects.parse(await getJson(ctx, `${base(ctx.env)}/api/0/organizations/${o}/projects/`, token));
    const slugOf = new Map(projects.map((p) => [p.id, p.slug]));
    const stats = Stats.parse(await getJson(ctx, `${base(ctx.env)}/api/0/organizations/${o}/stats_v2/?field=sum(quantity)&category=error&outcome=accepted&interval=1h&statsPeriod=48h&groupBy=project`, token));

    const buckets: RuntimeBucket[] = [];
    const last = new Map<string, RuntimeBucket>();
    for (const g of stats.groups) {
      const key = slugOf.get(g.by.project);
      const series = g.series["sum(quantity)"];
      if (!key || !series) continue;
      series.forEach((count, i) => {
        const ts = Date.parse(stats.intervals[i] ?? "");
        if (Number.isNaN(ts)) return;
        const b: RuntimeBucket = { source: "sentry", key, ts, errors: count / 60 }; // per minute
        buckets.push(b);
        last.set(key, b);
      });
    }
    // name the culprits on each project's newest bucket (only where something is actually erroring)
    await Promise.all([...last].map(async ([key, b]) => {
      if (!b.errors) return;
      try {
        const issues = Issues.parse(await getJson(ctx, `${base(ctx.env)}/api/0/projects/${o}/${encodeURIComponent(key)}/issues/?query=is:unresolved&statsPeriod=24h&sort=freq&limit=3`, token));
        b.top = issues.map((i) => ({ title: i.title.slice(0, 120), count: i.count, url: i.permalink }));
      } catch { /* the numbers still stand without the issue list */ }
    }));
    return { buckets };
  },
};
