import { parse, parseAllDocuments } from "yaml";
import { IMAGE_DATASTORES, TF_RESOURCES } from "../knowledge";
import type { Detector, RawEdge, RawNode } from "../types";
import { baseOf, dirOf, lineOf, lines, manifestDirs, owningDir, pkgId, slug } from "../util";

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);
const asArr = (v: unknown): unknown[] => (Array.isArray(v) ? v : v === undefined ? [] : [v]);

function datastoreFor(image: string) {
  for (const [re, label, kind] of IMAGE_DATASTORES) if (re.test(image)) return { label, kind };
  return null;
}

export const infraDetector: Detector = {
  name: "Infrastructure",
  async detect(ctx) {
    const nodes: RawNode[] = [];
    const edges: RawEdge[] = [];
    const dirs = manifestDirs(ctx.files);
    const pkgFor = (dir: string) => { const d = owningDir(dir + "/x", dirs); return d === undefined ? undefined : pkgId(d); };

    // ---- Dockerfiles ----
    for (const f of ctx.files.filter((p) => /(^|\/)(Dockerfile(\.[\w.-]+)?|[\w.-]+\.Dockerfile)$/.test(p))) {
      const text = await ctx.read(f);
      if (!text) continue;
      const froms = [...text.matchAll(/^FROM\s+(?:--platform=\S+\s+)?(\S+)/gim)].map((m) => m[1]);
      const ports = [...text.matchAll(/^EXPOSE\s+(.+)$/gim)].flatMap((m) => m[1].trim().split(/\s+/));
      const id = `docker:${f}`;
      nodes.push({
        id, kind: "service", group: "infra", label: `Container image${dirOf(f) ? ` (${dirOf(f)})` : ""}`,
        summary: `Built from ${froms.at(-1) ?? "unknown base"}${froms.length > 1 ? `, ${froms.length} stages` : ""}${ports.length ? `, exposes ${ports.join(", ")}` : ""}.`,
        evidence: [{ path: f, lines: lines(lineOf(text, /^FROM/im)) }],
      });
      const owner = pkgFor(dirOf(f));
      if (owner) edges.push({ from: owner, to: id, kind: "deploys_to" });
    }

    // ---- docker compose ----
    for (const f of ctx.files.filter((p) => /(^|\/)(docker-compose[\w.-]*|compose[\w.-]*)\.ya?ml$/.test(p))) {
      const text = await ctx.read(f);
      if (!text) continue;
      let doc: unknown;
      try { doc = parse(text); } catch { continue; }
      if (!isObj(doc) || !isObj(doc.services)) continue;
      const nodeIdFor = (name: string) => {
        const svc = (doc as { services: Record<string, Obj> }).services[name];
        const ds = typeof svc?.image === "string" ? datastoreFor(svc.image) : null;
        return ds ? `ds:${slug(ds.label)}` : `compose:${f}:${name}`;
      };
      for (const [name, svc] of Object.entries(doc.services as Record<string, Obj>)) {
        if (!isObj(svc)) continue;
        const line = lineOf(text, new RegExp(`^\\s{2,4}${name}:`, "m"));
        const image = typeof svc.image === "string" ? svc.image : undefined;
        const ds = image ? datastoreFor(image) : null;
        const id = nodeIdFor(name);
        if (ds) {
          nodes.push({
            id, kind: ds.kind, group: "data", label: ds.label,
            summary: `Runs as ${image} in docker compose.`, evidence: [{ path: f, lines: lines(line) }],
          });
        } else {
          const ports = asArr(svc.ports).map(String);
          nodes.push({
            id, kind: "service", group: "infra", label: name,
            summary: `Compose service${image ? ` (${image})` : svc.build ? " built from source" : ""}${ports.length ? `, ports ${ports.join(", ")}` : ""}.`,
            evidence: [{ path: f, lines: lines(line) }],
          });
          const ctxDir = typeof svc.build === "string" ? svc.build : isObj(svc.build) && typeof svc.build.context === "string" ? svc.build.context : undefined;
          if (ctxDir) {
            const rel = [dirOf(f), ctxDir].filter(Boolean).join("/").replace(/\/\.$/, "").replace(/(^|\/)\.\//g, "$1").replace(/^\.$/, "");
            const owner = pkgFor(rel === "." ? "" : rel);
            if (owner) edges.push({ from: owner, to: id, kind: "deploys_to" });
          }
        }
        const deps = isObj(svc.depends_on) ? Object.keys(svc.depends_on) : asArr(svc.depends_on).map(String);
        for (const d of deps) edges.push({ from: id, to: nodeIdFor(d), kind: "depends_on" });
      }
    }

    // ---- Kubernetes ----
    const k8s: { kind: string; name: string; file: string; line?: number; obj: Obj }[] = [];
    for (const f of ctx.files.filter((p) => /\.ya?ml$/.test(p) && !p.startsWith(".github/") && !/docker-compose|compose\./.test(p))) {
      const text = await ctx.read(f);
      if (!text || !/^apiVersion:/m.test(text) || !/^kind:/m.test(text) || /\{\{/.test(text)) continue;
      for (const d of parseAllDocuments(text)) {
        if (d.errors.length) continue;
        const o = d.toJS() as unknown;
        if (!isObj(o) || typeof o.kind !== "string" || !isObj(o.metadata) || typeof o.metadata.name !== "string") continue;
        if (["Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "Service", "Ingress"].includes(o.kind)) {
          k8s.push({ kind: o.kind, name: o.metadata.name, file: f, line: lineOf(text, new RegExp(`^kind:\\s*${o.kind}`, "m")), obj: o });
        }
      }
    }
    const k8sId = (kind: string, name: string) => `k8s:${kind}:${name}`;
    for (const r of k8s) {
      nodes.push({
        id: k8sId(r.kind, r.name), group: "infra", label: r.name,
        kind: r.kind === "Ingress" ? "endpoint" : r.kind === "CronJob" || r.kind === "Job" ? "job" : "service",
        summary: `Kubernetes ${r.kind}${r.kind === "Deployment" ? `, ${(r.obj.spec as Obj | undefined)?.replicas ?? 1} replica(s)` : ""}.`,
        evidence: [{ path: r.file, lines: lines(r.line) }],
      });
    }
    const labelsOf = (o: Obj) => (((o.spec as Obj | undefined)?.template as Obj | undefined)?.metadata as Obj | undefined)?.labels as Record<string, string> | undefined;
    for (const svc of k8s.filter((r) => r.kind === "Service")) {
      const sel = (svc.obj.spec as Obj | undefined)?.selector as Record<string, string> | undefined;
      if (!sel) continue;
      for (const w of k8s.filter((r) => ["Deployment", "StatefulSet", "DaemonSet"].includes(r.kind))) {
        const l = labelsOf(w.obj);
        if (l && Object.entries(sel).every(([k, v]) => l[k] === v)) edges.push({ from: k8sId("Service", svc.name), to: k8sId(w.kind, w.name), kind: "calls" });
      }
    }
    for (const ing of k8s.filter((r) => r.kind === "Ingress")) {
      const text = JSON.stringify(ing.obj);
      for (const m of text.matchAll(/"service":\{"name":"([^"]+)"/g)) edges.push({ from: k8sId("Ingress", ing.name), to: k8sId("Service", m[1]), kind: "calls" });
    }

    // ---- Terraform ----
    let tfCount = 0;
    for (const f of ctx.files.filter((p) => p.endsWith(".tf"))) {
      const text = await ctx.read(f);
      if (!text) continue;
      for (const m of text.matchAll(/^resource\s+"(\w+)"\s+"([\w-]+)"/gm)) {
        const hit = TF_RESOURCES.find(([re]) => re.test(m[1]));
        if (!hit || tfCount >= 40) continue;
        tfCount++;
        const [, label, kind] = hit;
        const isData = kind === "datastore" || kind === "queue";
        nodes.push({
          id: `tf:${m[1]}.${m[2]}`, kind: kind === "external" ? "external" : kind, group: isData ? "data" : "infra",
          label: `${label}: ${m[2]}`, summary: `Terraform resource ${m[1]}.${m[2]}.`,
          evidence: [{ path: f, lines: lines(text.slice(0, m.index).split("\n").length) }],
        });
      }
    }

    // ---- platform configs ----
    for (const f of ctx.files) {
      const b = baseOf(f);
      const dir = dirOf(f);
      const owner = pkgFor(dir);
      if (b === "vercel.json") {
        const text = await ctx.read(f);
        let cfg: Obj = {};
        try { cfg = JSON.parse(text ?? "{}"); } catch { /* ignore */ }
        const crons = asArr(cfg.crons).length;
        const id = `vercel:${dir || "."}`;
        nodes.push({
          id, kind: "service", group: "infra", label: `Vercel project${dir ? ` (${dir})` : ""}`,
          summary: `Deploys to Vercel${crons ? `, ${crons} cron job${crons > 1 ? "s" : ""}` : ""}.`, evidence: [{ path: f }],
        });
        if (owner) edges.push({ from: owner, to: id, kind: "deploys_to" });
      } else if (b === "fly.toml" || b === "netlify.toml" || b === "render.yaml" || b === "Procfile" || b === "app.yaml") {
        const label = { "fly.toml": "Fly.io app", "netlify.toml": "Netlify site", "render.yaml": "Render services", Procfile: "Procfile processes", "app.yaml": "App Engine service" }[b]!;
        const id = `plat:${slug(f)}`;
        nodes.push({ id, kind: "service", group: "infra", label: `${label}${dir ? ` (${dir})` : ""}`, summary: `Deployment config (${b}).`, evidence: [{ path: f }] });
        if (owner) edges.push({ from: owner, to: id, kind: "deploys_to" });
      } else if (b === "serverless.yml" || b === "serverless.yaml") {
        const text = await ctx.read(f);
        let cfg: Obj = {};
        try { cfg = (parse(text ?? "") as Obj) ?? {}; } catch { /* ignore */ }
        const fns = isObj(cfg.functions) ? Object.keys(cfg.functions) : [];
        const id = `sls:${dir || "."}`;
        nodes.push({ id, kind: "service", group: "infra", label: `Serverless app${dir ? ` (${dir})` : ""}`, summary: `${fns.length} function(s).`, evidence: [{ path: f }] });
        if (owner) edges.push({ from: owner, to: id, kind: "deploys_to" });
        for (const fn of fns.slice(0, 30)) {
          nodes.push({
            id: `${id}:${fn}`, parent: id, kind: "service", group: "infra", label: fn, summary: "Serverless function.",
            evidence: [{ path: f, lines: lines(lineOf(text ?? "", new RegExp(`^\\s+${fn}:`, "m"))) }],
          });
        }
      }
    }
    return { nodes, edges };
  },
};
