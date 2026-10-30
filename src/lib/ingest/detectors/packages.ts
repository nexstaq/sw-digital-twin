import { DATASTORE_LIBS, EXTERNAL_LIBS, FRAMEWORK_DEPS } from "../knowledge";
import type { Detector, DetectorContext, RawEdge, RawNode } from "../types";
import { baseOf, dirOf, lineOf, lines, pkgId, readJson, slug } from "../util";

interface PkgJson {
  name?: string; main?: string; bin?: string | Record<string, string>; workspaces?: string[] | { packages?: string[] };
  scripts?: Record<string, string>; dependencies?: Record<string, string>; devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

/** "app"/"main" say nothing; the folder or repo name does */
const GENERIC = /^(app|main|src|project|web)$/i;
const normPy = (s: string) => s.toLowerCase().replace(/\[.*$/, "").replace(/[<>=!~;\s].*$/, "").replace(/_/g, "-").replace(/-binary$/, "");

function pyDeps(text: string, file: string): string[] {
  if (baseOf(file) === "requirements.txt") {
    return text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#") && !l.startsWith("-")).map(normPy);
  }
  // pyproject: dependencies = [ "fastapi[standard]>=1", ... ]. Entries contain ']', so walk the array, tracking strings.
  const out: string[] = [];
  for (const m of text.matchAll(/^\s*(?:optional-)?dependencies\s*=\s*\[/gm)) {
    let i = m.index! + m[0].length;
    let quote = "";
    let cur = "";
    for (; i < text.length; i++) {
      const c = text[i];
      if (quote) {
        if (c === quote) { out.push(normPy(cur)); quote = ""; cur = ""; } else cur += c;
      } else if (c === '"' || c === "'") quote = c;
      else if (c === "]") break;
    }
  }
  const poetry = /\[tool\.poetry\.dependencies\]([\s\S]*?)(?:\n\[|$)/.exec(text);
  if (poetry) for (const m of poetry[1].matchAll(/^([\w.-]+)\s*=/gm)) out.push(normPy(m[1]));
  return out;
}

function goDeps(text: string): string[] {
  return [...text.matchAll(/^\s*([\w./~-]+\.[\w./~-]+)\s+v[\w.+-]+/gm)].map((m) => m[1]);
}

const GO_MAP: [RegExp, { ds?: [string, "datastore" | "queue"]; ext?: string; fw?: string }][] = [
  [/lib\/pq|jackc\/pgx/, { ds: ["PostgreSQL", "datastore"] }], [/go-redis|redis\/go-redis/, { ds: ["Redis", "datastore"] }],
  [/mongo-driver/, { ds: ["MongoDB", "datastore"] }], [/go-sql-driver\/mysql/, { ds: ["MySQL", "datastore"] }],
  [/segmentio\/kafka-go|confluent-kafka-go|Shopify\/sarama/, { ds: ["Kafka", "queue"] }], [/streadway\/amqp|rabbitmq\/amqp091/, { ds: ["RabbitMQ", "queue"] }],
  [/stripe\/stripe-go/, { ext: "Stripe" }], [/gin-gonic\/gin/, { fw: "Gin" }], [/labstack\/echo/, { fw: "Echo" }], [/gofiber\/fiber/, { fw: "Fiber" }],
  [/go-chi\/chi/, { fw: "chi" }], [/gorilla\/mux/, { fw: "gorilla/mux" }],
];

export async function readPackageNames(ctx: DetectorContext, dirs: string[]): Promise<Map<string, string>> {
  const names = new Map<string, string>(); // package name -> dir
  for (const d of dirs) {
    const j = await readJson<PkgJson>(ctx, d ? `${d}/package.json` : "package.json");
    if (j?.name) names.set(j.name, d);
  }
  return names;
}

export const packagesDetector: Detector = {
  name: "Packages & dependencies",
  async detect(ctx) {
    const nodes: RawNode[] = [];
    const edges: RawEdge[] = [];
    const hasFile = (p: string) => ctx.files.includes(p);
    const manifests = ctx.files.filter((f) => ["package.json", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml"].includes(baseOf(f)));
    const dirs = [...new Set(manifests.map(dirOf))].sort();
    const names = await readPackageNames(ctx, dirs);
    const isMonorepo = dirs.length > 1;
    const libs: RawNode[] = [];

    const addDep = (pid: string, file: string, text: string, needle: string, hit: { ds?: [string, "datastore" | "queue"]; ext?: string }) => {
      const ev = [{ path: file, lines: lines(lineOf(text, needle)) }];
      if (hit.ds) {
        const [label, kind] = hit.ds;
        nodes.push({ id: `ds:${slug(label)}`, kind, group: "data", label, summary: `Used by this codebase (dependency ${needle}).`, evidence: ev });
        edges.push({ from: pid, to: `ds:${slug(label)}`, kind: kind === "queue" ? "publishes" : "reads" });
      }
      if (hit.ext) {
        nodes.push({ id: `ext:${slug(hit.ext)}`, kind: "external", group: "external", label: hit.ext, summary: `Third-party service used via ${needle}.`, evidence: ev });
        edges.push({ from: pid, to: `ext:${slug(hit.ext)}`, kind: "calls" });
      }
    };

    for (const dir of dirs) {
      const prefix = dir ? `${dir}/` : "";
      const pj = hasFile(`${prefix}package.json`) ? await readJson<PkgJson>(ctx, `${prefix}package.json`) : null;
      const hasDocker = ctx.files.some((f) => dirOf(f) === dir && /^Dockerfile/.test(baseOf(f)));
      const id = pkgId(dir);
      const frameworks = new Set<string>();
      let primary = `${prefix}package.json`;
      let primaryText = "";
      let deps: string[] = [];
      const mapped: { lib: string; hit: { ds?: [string, "datastore" | "queue"]; ext?: string } }[] = [];

      if (pj) {
        const wsRaw = Array.isArray(pj.workspaces) ? pj.workspaces : pj.workspaces?.packages;
        const isRoot = !!wsRaw?.length || (dir === "" && (hasFile("pnpm-workspace.yaml") || hasFile("lerna.json")));
        const all = { ...pj.peerDependencies, ...pj.devDependencies, ...pj.dependencies };
        deps = Object.keys(all);
        primaryText = (await ctx.read(primary)) ?? "";
        for (const d of Object.keys({ ...pj.dependencies, ...pj.devDependencies })) if (FRAMEWORK_DEPS[d]) frameworks.add(FRAMEWORK_DEPS[d]);
        for (const d of Object.keys({ ...pj.dependencies, ...pj.peerDependencies })) {
          if (DATASTORE_LIBS[d]) mapped.push({ lib: d, hit: { ds: [DATASTORE_LIBS[d].label, DATASTORE_LIBS[d].kind] } });
          if (EXTERNAL_LIBS[d]) mapped.push({ lib: d, hit: { ext: EXTERNAL_LIBS[d] } });
          const target = names.get(d);
          if (target !== undefined && target !== dir) edges.push({ from: id, to: pkgId(target), kind: "depends_on" });
        }
        if (isRoot) continue; // workspace root is a container, not a component
        const runnable = !!pj.scripts?.start || !!pj.bin || hasDocker || [...frameworks].some((f) => /Next|Express|Fastify|Hono|Koa|Nest|Remix|Nuxt|SvelteKit|Astro|Vite|Electron|Expo/.test(f));
        const node: RawNode = {
          id, group: "service", kind: runnable ? "service" : "package", label: pj.name && !GENERIC.test(pj.name) ? pj.name : dir ? baseOf(dir) : ctx.repo.split("/").pop()!,
          summary: `${[...frameworks].slice(0, 3).join(" + ") || (runnable ? "Application" : "Library")} · ${deps.length} dependencies.`,
          evidence: [{ path: primary }],
        };
        (runnable || !isMonorepo ? nodes : libs).push(node);
      } else {
        // python / go / rust
        const py = ["pyproject.toml", "requirements.txt"].map((n) => `${prefix}${n}`).filter(hasFile);
        const go = hasFile(`${prefix}go.mod`) ? `${prefix}go.mod` : null;
        const cargo = hasFile(`${prefix}Cargo.toml`) ? `${prefix}Cargo.toml` : null;
        if (py.length) {
          primary = py[0];
          primaryText = (await ctx.read(primary)) ?? "";
          for (const f of py) deps.push(...pyDeps((await ctx.read(f)) ?? "", f));
          for (const d of deps) {
            if (FRAMEWORK_DEPS[d]) frameworks.add(FRAMEWORK_DEPS[d]);
            if (DATASTORE_LIBS[d]) mapped.push({ lib: d, hit: { ds: [DATASTORE_LIBS[d].label, DATASTORE_LIBS[d].kind] } });
            if (EXTERNAL_LIBS[d]) mapped.push({ lib: d, hit: { ext: EXTERNAL_LIBS[d] } });
          }
          const declared = /^name\s*=\s*["']([^"']+)["']/m.exec(primaryText)?.[1];
          // "app"/"main" say nothing; the folder name does
          const name = declared && !GENERIC.test(declared) ? declared : dir ? baseOf(dir) : ctx.repo.split("/").pop()!;
          nodes.push({
            id, group: "service", kind: "service", label: name,
            summary: `${[...frameworks].join(" + ") || "Python"} · ${deps.length} dependencies.`, evidence: [{ path: primary }],
          });
        } else if (go) {
          primary = go; primaryText = (await ctx.read(go)) ?? "";
          const mod = /^module\s+(\S+)/m.exec(primaryText)?.[1] ?? (dir || "go module");
          deps = goDeps(primaryText);
          for (const d of deps) for (const [re, h] of GO_MAP) if (re.test(d)) {
            if (h.fw) frameworks.add(h.fw);
            if (h.ds || h.ext) mapped.push({ lib: d, hit: h });
          }
          nodes.push({ id, group: "service", kind: "service", label: mod.split("/").slice(-2).join("/"), summary: `${[...frameworks].join(" + ") || "Go"} · ${deps.length} dependencies.`, evidence: [{ path: go }] });
        } else if (cargo) {
          primary = cargo; primaryText = (await ctx.read(cargo)) ?? "";
          const name = /^name\s*=\s*"([^"]+)"/m.exec(primaryText)?.[1] ?? (dir || "rust crate");
          nodes.push({ id, group: "service", kind: "service", label: name, summary: "Rust crate.", evidence: [{ path: cargo }] });
        } else continue;
      }
      for (const { lib, hit } of mapped) addDep(id, primary, primaryText, lib, hit);
    }

    // many shared libs would drown the map: fold them into one component
    if (libs.length >= 3) {
      nodes.push({
        id: "cl:libs", group: "service", kind: "package", label: "Shared packages",
        summary: `${libs.length} internal libraries used across the repo.`, evidence: [libs[0].evidence[0]],
      });
      for (const l of libs) nodes.push({ ...l, parent: "cl:libs" });
    } else nodes.push(...libs);

    return { nodes, edges };
  },
};
