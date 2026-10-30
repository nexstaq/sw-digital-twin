import { z } from "zod";
import type { DeploySignal, DeployState } from "@/lib/health/signals";
import { getJson } from "./http";
import type { Connector } from "./types";

/**
 * Vercel deployments for one project (VERCEL_PROJECT_ID) -> deploy health on the matching environment node.
 * Runtime logs are not read. NOTE: tested against a mock of the documented response, not a live account.
 */
const Deployments = z.object({
  deployments: z.array(z.object({
    uid: z.string(), name: z.string().optional(), url: z.string().optional(), created: z.number(), target: z.string().nullish(),
    state: z.string().optional(), readyState: z.string().optional(), inspectorUrl: z.string().nullish(),
    meta: z.record(z.string(), z.string()).nullish(),
  })),
});

const STATE: Record<string, DeployState> = {
  READY: "success", ERROR: "failure", BUILDING: "in_progress", INITIALIZING: "in_progress", QUEUED: "queued", CANCELED: "inactive",
};
const base = (env: NodeJS.ProcessEnv) => (env.VERCEL_API_URL ?? "https://api.vercel.com").replace(/\/$/, "");
const team = (env: NodeJS.ProcessEnv) => (env.VERCEL_TEAM_ID ? `&teamId=${encodeURIComponent(env.VERCEL_TEAM_ID)}` : "");

export const vercel: Connector = {
  id: "vercel", label: "Vercel", needs: ["VERCEL_TOKEN", "VERCEL_PROJECT_ID"],
  configured: (env) => !!(env.VERCEL_TOKEN && env.VERCEL_PROJECT_ID),
  async discover(ctx) { return [{ source: "vercel", key: ctx.env.VERCEL_PROJECT_ID ?? "", name: `Vercel project ${ctx.env.VERCEL_PROJECT_ID}` }]; },
  async poll(ctx) {
    const { VERCEL_TOKEN: token = "", VERCEL_PROJECT_ID: project = "" } = ctx.env;
    const res = Deployments.parse(await getJson(ctx, `${base(ctx.env)}/v6/deployments?projectId=${encodeURIComponent(project)}&limit=20${team(ctx.env)}`, token));
    const deploys: DeploySignal[] = res.deployments.map((d) => ({
      id: Number.parseInt(d.uid.replace(/\D/g, "").slice(0, 12) || "0", 10) || d.created,
      environment: d.target === "production" ? "production" : (d.target ?? "preview"),
      sha: d.meta?.githubCommitSha ?? d.uid,
      state: STATE[(d.state ?? d.readyState ?? "").toUpperCase()] ?? "unknown",
      createdAt: new Date(d.created).toISOString(),
      url: d.inspectorUrl ?? (d.url ? `https://${d.url}` : "https://vercel.com"),
    }));
    return { deploys };
  },
};
