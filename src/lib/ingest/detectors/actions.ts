import { LineCounter, parseDocument, isMap, isScalar } from "yaml";
import type { Detector, RawEdge, RawNode } from "../types";
import { baseOf, lines, manifestDirs, pkgId, slug } from "../util";

const DEPLOY_USES: [RegExp, string][] = [
  [/vercel/i, "Vercel"], [/aws-actions|amazon-ecs|configure-aws/i, "AWS"], [/google-github-actions\/(deploy|auth)|gcloud/i, "Google Cloud"],
  [/azure\/(webapps|aks|container)/i, "Azure"], [/cloudflare\/(wrangler|pages)/i, "Cloudflare"], [/superfly\/flyctl/i, "Fly.io"],
  [/peaceiris\/actions-gh-pages|actions\/deploy-pages/i, "GitHub Pages"], [/netlify/i, "Netlify"], [/docker\/build-push-action/i, "Container registry"],
  [/pypa\/gh-action-pypi-publish/i, "PyPI"], [/npm publish/i, "npm registry"],
];
const DEPLOY_RUN: [RegExp, string][] = [
  [/\bvercel\b.*(--prod|deploy)/i, "Vercel"], [/\b(kubectl|helm)\s+(apply|upgrade)/i, "Kubernetes"], [/\bterraform\s+apply/i, "Terraform"],
  [/\bflyctl?\s+deploy/i, "Fly.io"], [/\bnpm\s+publish|pnpm\s+publish/i, "npm registry"], [/\bgcloud\s+.*deploy/i, "Google Cloud"],
  [/\baws\s+(ecs|lambda|s3\s+sync)/i, "AWS"], [/\bwrangler\s+(deploy|publish)/i, "Cloudflare"], [/docker\s+push/i, "Container registry"],
];

const str = (v: unknown) => (typeof v === "string" ? v : undefined);

export const actionsDetector: Detector = {
  name: "GitHub Actions",
  async detect(ctx) {
    const nodes: RawNode[] = [];
    const edges: RawEdge[] = [];
    const pkgDirs = manifestDirs(ctx.files).filter(Boolean);
    const addDir = (from: string, hint: string) => {
      const h = hint.replace(/^\.?\//, "").replace(/\/\*{0,2}.*$/, "").replace(/\/$/, "");
      const hit = pkgDirs.find((d) => h === d || h.startsWith(d + "/") || d.startsWith(h + "/"));
      if (hit) edges.push({ from, to: pkgId(hit), kind: "triggers" });
    };

    for (const file of ctx.files.filter((f) => /^\.github\/workflows\/[^/]+\.ya?ml$/.test(f))) {
      const text = await ctx.read(file);
      if (!text) continue;
      const lc = new LineCounter();
      const doc = parseDocument(text, { lineCounter: lc });
      if (doc.errors.length) continue;
      const root = doc.toJS() as Record<string, unknown> | null;
      if (!root || typeof root !== "object") continue;

      const wfId = `wf:${file}`;
      const rawOn = (root.on ?? root[true as unknown as string]) as unknown;
      const triggers = typeof rawOn === "string" ? [rawOn] : Array.isArray(rawOn) ? rawOn.map(String) : rawOn && typeof rawOn === "object" ? Object.keys(rawOn) : [];
      const wfName = str(root.name) ?? baseOf(file).replace(/\.ya?ml$/, "");
      nodes.push({
        id: wfId, kind: "job", label: wfName, group: "ci",
        summary: triggers.length ? `Runs on ${triggers.join(", ")}.` : "GitHub Actions workflow.",
        evidence: [{ path: file, lines: "1" }],
      });

      // path filters point at the packages this workflow cares about
      const on = rawOn as Record<string, { paths?: string[] }> | undefined;
      for (const t of ["push", "pull_request"]) for (const p of on?.[t]?.paths ?? []) addDir(wfId, p);

      const jobs = (root.jobs ?? {}) as Record<string, Record<string, unknown>>;
      const jobsNode = doc.get("jobs", true);
      for (const [jobKey, job] of Object.entries(jobs)) {
        if (!job || typeof job !== "object") continue;
        let line: number | undefined;
        if (isMap(jobsNode)) {
          const pair = jobsNode.items.find((i) => isScalar(i.key) && i.key.value === jobKey);
          const r = isScalar(pair?.key) ? pair.key.range : undefined;
          if (r) line = lc.linePos(r[0]).line;
        }
        const jobId = `job:${file}:${jobKey}`;
        const steps = Array.isArray(job.steps) ? (job.steps as Record<string, unknown>[]) : [];
        const runner = Array.isArray(job["runs-on"]) ? (job["runs-on"] as string[]).join(", ") : str(job["runs-on"]);
        nodes.push({
          id: jobId, parent: wfId, kind: "job", group: "ci", label: str(job.name) ?? jobKey,
          summary: `${steps.length} step${steps.length === 1 ? "" : "s"}${runner ? ` on ${runner}` : ""}.`,
          evidence: [{ path: file, lines: lines(line) }],
        });

        const needs = job.needs === undefined ? [] : Array.isArray(job.needs) ? job.needs.map(String) : [String(job.needs)];
        for (const n of needs) edges.push({ from: `job:${file}:${n}`, to: jobId, kind: "triggers" });

        const env = typeof job.environment === "string" ? job.environment : str((job.environment as { name?: string } | undefined)?.name);
        if (env && !env.includes("${{")) {
          nodes.push({
            id: `env:${slug(env)}`, kind: "env", group: "ci", label: `${env} environment`,
            summary: "Deployment environment referenced by a workflow.", evidence: [{ path: file, lines: lines(line) }],
          });
          edges.push({ from: jobId, to: `env:${slug(env)}`, kind: "deploys_to" });
        }

        const wd = str((job.defaults as { run?: { "working-directory"?: string } } | undefined)?.run?.["working-directory"]);
        if (wd) addDir(jobId, wd);

        const targets = new Set<string>();
        for (const step of steps) {
          const uses = str(step.uses) ?? "";
          const run = str(step.run) ?? "";
          for (const [re, label] of DEPLOY_USES) if (re.test(uses) || (label === "npm registry" && re.test(run))) targets.add(label);
          for (const [re, label] of DEPLOY_RUN) if (re.test(run)) targets.add(label);
          const stepWd = str(step["working-directory"]);
          if (stepWd) addDir(jobId, stepWd);
          const cd = /\bcd\s+([\w./-]+)/.exec(run);
          if (cd) addDir(jobId, cd[1]);
          const filter = /--filter[= ]([\w@./-]+)/.exec(run);
          if (filter) addDir(jobId, filter[1].replace(/^@[^/]+\//, ""));
        }
        for (const t of targets) {
          nodes.push({
            id: `target:${slug(t)}`, kind: "external", group: "ci", label: `Deploys to ${t}`,
            summary: "Delivery target detected from workflow steps.", evidence: [{ path: file, lines: lines(line) }],
          });
          edges.push({ from: jobId, to: `target:${slug(t)}`, kind: "deploys_to" });
        }
      }
    }
    return { nodes, edges };
  },
};

