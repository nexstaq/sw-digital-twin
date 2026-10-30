import { z } from "zod";
import type { DeploySignal, DeployState, JobSignal, RunSignal, SignalSet } from "@/lib/health/signals";

/** GITHUB_API_URL lets this point at GitHub Enterprise Server (and at a mock in tests). */
const base = () => (process.env.GITHUB_API_URL ?? "https://api.github.com").replace(/\/$/, "");

export class GitHubError extends Error {
  constructor(message: string, readonly status: number, readonly retryAt?: number) { super(message); }
  /** retrying will not help (bad repo, no access) */
  get fatal() { return this.status === 404 || this.status === 401; }
}

const Repo = z.object({ default_branch: z.string() });
const Runs = z.object({
  workflow_runs: z.array(z.object({
    id: z.number(), path: z.string().nullish(), name: z.string().nullish(), head_branch: z.string().nullish(), head_sha: z.string(),
    event: z.string(), status: z.string().nullable(), conclusion: z.string().nullable(), run_attempt: z.number().nullish(),
    created_at: z.string(), updated_at: z.string().nullish(), html_url: z.string(),
  })),
});
const Jobs = z.object({
  jobs: z.array(z.object({
    name: z.string(), status: z.string(), conclusion: z.string().nullable(), html_url: z.string().nullish(),
    steps: z.array(z.object({ name: z.string(), conclusion: z.string().nullable() })).nullish(),
  })),
});
const Deployments = z.array(z.object({ id: z.number(), environment: z.string(), sha: z.string(), created_at: z.string(), url: z.string() }));
const Statuses = z.array(z.object({ state: z.string(), log_url: z.string().nullish(), target_url: z.string().nullish() }));

const DEPLOY_STATES = new Set<DeployState>(["success", "failure", "error", "in_progress", "queued", "pending", "inactive"]);

export interface FetchOpts { token?: string; fetch?: typeof fetch }

async function gh<T>(path: string, schema: z.ZodType<T>, o: FetchOpts): Promise<T> {
  const res = await (o.fetch ?? fetch)(`${base()}${path}`, {
    headers: {
      accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "sw-digital-twin",
      ...(o.token ? { authorization: `Bearer ${o.token}` } : {}),
    },
    cache: "no-store",
  });
  if (!res.ok) {
    const reset = Number(res.headers.get("x-ratelimit-reset")) * 1000 || undefined;
    if (res.status === 429 || (res.status === 403 && res.headers.get("x-ratelimit-remaining") === "0")) {
      throw new GitHubError(`GitHub rate limit reached${o.token ? "" : ". Set GITHUB_TOKEN or install the GitHub App for a higher limit"}.`, 429, reset);
    }
    if (res.status === 404) throw new GitHubError("GitHub says this repository does not exist or is private. Install the GitHub App to read private repositories.", 404);
    throw new GitHubError(`GitHub returned ${res.status}.`, res.status);
  }
  return schema.parse(await res.json());
}

const MAX_JOB_LOOKUPS = 8; // workflows whose latest run we open up
const MAX_DEPLOY_LOOKUPS = 8;

/** Pulls the live signals the health engine needs. About 3 + (workflows) + (deployments) requests. */
export async function fetchSignals(repo: string, o: FetchOpts = {}): Promise<SignalSet> {
  const info = await gh(`/repos/${repo}`, Repo, o);
  const branch = info.default_branch;

  const [runsRes, deployRes] = await Promise.all([
    gh(`/repos/${repo}/actions/runs?per_page=100&branch=${encodeURIComponent(branch)}&exclude_pull_requests=true`, Runs, o),
    gh(`/repos/${repo}/deployments?per_page=30`, Deployments, o).catch((e) => { if (e instanceof GitHubError && e.status === 404) return []; throw e; }),
  ]);

  const runs: RunSignal[] = runsRes.workflow_runs.map((r) => ({
    id: r.id, workflowPath: r.path ?? "", workflowName: r.name ?? r.path ?? "workflow", branch: r.head_branch ?? "", sha: r.head_sha, event: r.event,
    status: r.status ?? "unknown", conclusion: r.conclusion, attempt: r.run_attempt ?? 1, createdAt: r.created_at, completedAt: r.updated_at ?? undefined, url: r.html_url,
  }));

  // open up the latest finished run of each workflow, so failures can name the job and step
  const latest = new Map<string, RunSignal>();
  for (const r of runs) if (r.status === "completed" && r.workflowPath && !latest.has(r.workflowPath)) latest.set(r.workflowPath, r);
  // ...and the most recent failures, so replaying an incident can still name the failing step
  const failed = runs.filter((r) => r.status === "completed" && (r.conclusion === "failure" || r.conclusion === "timed_out") && !latest.has(r.workflowPath)).slice(0, 4);
  const lookups = [...new Set([...latest.values(), ...failed])].slice(0, MAX_JOB_LOOKUPS + 4);
  await Promise.all(lookups.map(async (r) => {
    try {
      const { jobs } = await gh(`/repos/${repo}/actions/runs/${r.id}/jobs?per_page=100&filter=latest`, Jobs, o);
      r.jobs = jobs.map((j): JobSignal => ({
        name: j.name, status: j.status, conclusion: j.conclusion, url: j.html_url ?? r.url,
        failedStep: j.steps?.find((s) => s.conclusion === "failure")?.name,
      }));
    } catch (e) { if (e instanceof GitHubError && e.status === 429) throw e; /* jobs are an enhancement; run-level health still works */ }
  }));

  const deploys: DeploySignal[] = await Promise.all(deployRes.slice(0, MAX_DEPLOY_LOOKUPS).map(async (d) => {
    let state: DeployState = "unknown";
    let url = `https://github.com/${repo}/deployments`;
    try {
      const [s] = await gh(`/repos/${repo}/deployments/${d.id}/statuses?per_page=1`, Statuses, o);
      if (s) { state = DEPLOY_STATES.has(s.state as DeployState) ? (s.state as DeployState) : "unknown"; url = s.target_url ?? s.log_url ?? url; }
    } catch (e) { if (e instanceof GitHubError && e.status === 429) throw e; }
    return { id: d.id, environment: d.environment, sha: d.sha, state, createdAt: d.created_at, url };
  }));

  return { repo, defaultBranch: branch, fetchedAt: Date.now(), runs, deploys };
}
