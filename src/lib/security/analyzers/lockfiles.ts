import { parse as parseYaml } from "yaml";
import type { SecurityContext } from "../types";

export type Ecosystem = "npm" | "PyPI" | "crates.io" | "Go";

export interface Pkg {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  /** the file it was found in (lockfile, or requirements.txt) */
  path: string;
  /** declared by the project's own manifest, rather than pulled in by something else */
  direct?: boolean;
  dev?: boolean;
  /** how a transitive package got here: the direct dependency, then each package between it and this one (empty for a direct dependency) */
  via?: string[];
  /** 1-based line in `path`, when the format makes that easy */
  line?: number;
}

const MAX_PACKAGES = 5000;

/** `name@1.2.3` style keys (pnpm, yarn): the name may start with @scope/. */
const splitKey = (k: string): { name: string; version: string } | null => {
  const m = /^\/?(@?[^@\s/]+(?:\/[^@\s/]+)?)@(\d[^()\s_]*)/.exec(k) ?? /^\/?(@?[^@\s]+?)\/(\d[^()\s_/]*)$/.exec(k);
  return m ? { name: m[1], version: m[2] } : null;
};

interface DepGraph {
  nodes: Map<string, { name: string; version: string }>;
  edges: Map<string, Set<string>>;
  prod: string[];
  dev: string[];
}

/**
 * Walks the dependency graph from your own manifests. A package reachable from `dependencies` ships; one reachable ONLY from
 * `devDependencies` is a development tool. `via` is the shortest chain from a direct dependency, which answers "why do I have this?".
 */
export function reach(g: DepGraph): Map<string, { dev: boolean; via: string[] }> {
  const out = new Map<string, { dev: boolean; via: string[] }>();
  const parent = new Map<string, string | null>();
  const walk = (roots: string[], dev: boolean) => {
    const queue: string[] = [];
    for (const r of roots) if (g.nodes.has(r) && !parent.has(r)) { parent.set(r, null); queue.push(r); }
    for (let i = 0; i < queue.length; i++) {
      const id = queue[i];
      const chain: string[] = [];
      for (let p = parent.get(id) ?? null; p; p = parent.get(p) ?? null) chain.unshift(g.nodes.get(p)!.name);
      out.set(id, { dev, via: chain });
      for (const next of g.edges.get(id) ?? []) if (g.nodes.has(next) && !parent.has(next)) { parent.set(next, id); queue.push(next); }
    }
  };
  walk(g.prod, false); // first: everything that ships
  walk(g.dev, true); // then what only development reaches
  return out;
}

function withGraph(pkgs: Pkg[], g: DepGraph, idOf: (p: Pkg) => string): Pkg[] {
  const r = reach(g);
  const rootNames = new Set([...g.prod, ...g.dev].map((id) => g.nodes.get(id)?.name).filter(Boolean));
  return pkgs.map((p) => {
    const hit = r.get(idOf(p));
    return hit ? { ...p, direct: rootNames.has(p.name), dev: hit.dev, via: hit.via } : p;
  });
}

interface NpmEntry { version?: string; dev?: boolean; link?: boolean; dependencies?: Record<string, string>; devDependencies?: Record<string, string>; optionalDependencies?: Record<string, string>; peerDependencies?: Record<string, string> }

/** npm resolves a dependency by looking in the package's own node_modules, then each parent's, up to the top. */
function npmResolve(all: Record<string, NpmEntry>, from: string, dep: string): string | null {
  for (let base = from; ; ) {
    const cand = base ? `${base}/node_modules/${dep}` : `node_modules/${dep}`;
    if (all[cand]?.version) return cand;
    if (!base) return null;
    base = base.includes("/node_modules/") ? base.slice(0, base.lastIndexOf("/node_modules/")) : "";
  }
}

function npmGraph(all: Record<string, NpmEntry>): DepGraph {
  const g: DepGraph = { nodes: new Map(), edges: new Map(), prod: [], dev: [] };
  for (const [key, v] of Object.entries(all)) {
    if (!key || v.link || !v.version) continue;
    g.nodes.set(key, { name: key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length), version: v.version });
    const deps = { ...v.dependencies, ...v.optionalDependencies, ...v.peerDependencies };
    g.edges.set(key, new Set(Object.keys(deps).map((d) => npmResolve(all, key, d)).filter((x): x is string => !!x)));
  }
  // roots: the project itself ("") and any workspace package, i.e. every entry that is not installed inside node_modules
  for (const [key, v] of Object.entries(all)) {
    if (key.includes("node_modules/") || v.link) continue;
    for (const d of Object.keys({ ...v.dependencies, ...v.optionalDependencies })) { const r = npmResolve(all, key, d); if (r) g.prod.push(r); }
    for (const d of Object.keys(v.devDependencies ?? {})) { const r = npmResolve(all, key, d); if (r) g.dev.push(r); }
  }
  return g;
}

function npmLock(text: string, path: string, directNames: Set<string>): Pkg[] {
  let j: { packages?: Record<string, { version?: string; dev?: boolean; link?: boolean }>; dependencies?: Record<string, { version?: string; dev?: boolean }> };
  try { j = JSON.parse(text); } catch { return []; }
  const out: Pkg[] = [];
  if (j.packages) {
    const all = j.packages as Record<string, NpmEntry>;
    const keyOf = new Map<Pkg, string>();
    for (const [key, v] of Object.entries(all)) {
      if (!key || v.link || !v.version) continue; // "" is the root project
      const name = key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
      if (!name) continue;
      const p: Pkg = { ecosystem: "npm", name, version: v.version, path, direct: directNames.has(name), dev: !!v.dev };
      keyOf.set(p, key);
      out.push(p);
    }
    return withGraph(out, npmGraph(all), (p) => keyOf.get(p)!);
  } else if (j.dependencies) { // lockfile v1
    const walk = (deps: Record<string, { version?: string; dev?: boolean; dependencies?: unknown }>) => {
      for (const [name, v] of Object.entries(deps)) {
        if (v.version) out.push({ ecosystem: "npm", name, version: v.version, path, direct: directNames.has(name), dev: !!v.dev });
        if (v.dependencies) walk(v.dependencies as typeof deps);
      }
    };
    walk(j.dependencies);
  }
  return out;
}

const stripPeers = (v: string) => v.replace(/\(.*$/, "");

/** `1.2.3(react@18)` -> id `name@1.2.3`; `npm:other@2.0.0` is an alias for another package; link/workspace/file refs are not packages. */
function pnpmRef(name: string, spec: unknown): { id: string; name: string; version: string } | null {
  const raw = typeof spec === "string" ? spec : (spec as { version?: string } | null)?.version;
  if (!raw) return null;
  const v = stripPeers(String(raw));
  if (/^(link|file|workspace|portal):/.test(v)) return null;
  const alias = /^(?:npm:)?(@?[^@\s]+)@(\d[^\s]*)$/.exec(v);
  const [n, ver] = alias ? [alias[1], alias[2]] : [name, v];
  return { id: `${n}@${ver}`, name: n, version: ver };
}

function pnpmLock(text: string, path: string, directNames: Set<string>): Pkg[] {
  let y: { packages?: Record<string, { dependencies?: Record<string, unknown>; optionalDependencies?: Record<string, unknown> }>; snapshots?: Record<string, { dependencies?: Record<string, unknown>; optionalDependencies?: Record<string, unknown> }>; importers?: Record<string, Record<string, Record<string, unknown> | undefined>>; dependencies?: Record<string, unknown>; devDependencies?: Record<string, unknown>; optionalDependencies?: Record<string, unknown> };
  try { y = parseYaml(text); } catch { return []; }
  const entries = y?.snapshots ?? y?.packages ?? {};
  const g: DepGraph = { nodes: new Map(), edges: new Map(), prod: [], dev: [] };
  const out = new Map<string, Pkg>();
  for (const [key, entry] of Object.entries(entries)) {
    const p = splitKey(stripPeers(key));
    if (!p) continue;
    const id = `${p.name}@${p.version}`;
    g.nodes.set(id, p);
    out.set(id, { ecosystem: "npm", name: p.name, version: p.version, path, direct: directNames.has(p.name) });
    const set = g.edges.get(id) ?? g.edges.set(id, new Set()).get(id)!;
    for (const [n, spec] of Object.entries({ ...entry?.dependencies, ...entry?.optionalDependencies })) { const r = pnpmRef(n, spec); if (r) set.add(r.id); }
  }
  // v6+ keep per-project sections under `importers`; v5 has them at the top level
  const roots = y?.importers ? Object.values(y.importers) : [y as Record<string, Record<string, unknown> | undefined>];
  for (const imp of roots) {
    for (const k of ["dependencies", "optionalDependencies"] as const) for (const [n, spec] of Object.entries(imp?.[k] ?? {})) { const r = pnpmRef(n, spec); if (r) g.prod.push(r.id); }
    for (const [n, spec] of Object.entries(imp?.devDependencies ?? {})) { const r = pnpmRef(n, spec); if (r) g.dev.push(r.id); }
  }
  const pkgs = [...out.values()];
  return g.prod.length || g.dev.length ? withGraph(pkgs, g, (p) => `${p.name}@${p.version}`) : pkgs;
}

function yarnLock(text: string, path: string, directNames: Set<string>): Pkg[] {
  const out: Pkg[] = [];
  const re = /^"?(@?[^@\s"]+)@[^\n]*:\n(?:[ \t]+[^\n]*\n)*?[ \t]+version:? "?([^"\n]+)"?/gm;
  for (let m: RegExpExecArray | null; (m = re.exec(text)); ) out.push({ ecosystem: "npm", name: m[1], version: m[2], path, direct: directNames.has(m[1]) });
  return out;
}

function requirements(text: string, path: string): Pkg[] {
  const out: Pkg[] = [];
  text.split("\n").forEach((raw, i) => {
    const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;#]*)/.exec(raw);
    if (m) out.push({ ecosystem: "PyPI", name: m[1].toLowerCase().replace(/_/g, "-"), version: m[2], path, direct: true, line: i + 1 });
  });
  return out;
}

function tomlPackages(text: string, path: string, ecosystem: Ecosystem, directNames: Set<string>): Pkg[] {
  const out: Pkg[] = [];
  const re = /\[\[package\]\]\s*\n(?:[^\[]*?)name\s*=\s*"([^"]+)"\s*\n\s*version\s*=\s*"([^"]+)"/g;
  for (let m: RegExpExecArray | null; (m = re.exec(text)); ) out.push({ ecosystem, name: ecosystem === "PyPI" ? m[1].toLowerCase().replace(/_/g, "-") : m[1], version: m[2], path, direct: directNames.has(m[1]) });
  return out;
}

function goMod(text: string, path: string): Pkg[] {
  const out: Pkg[] = [];
  let inBlock = false;
  text.split("\n").forEach((raw, i) => {
    const l = raw.replace(/\/\/.*$/, "").trim();
    if (/^require\s*\($/.test(l)) { inBlock = true; return; }
    if (inBlock && l === ")") { inBlock = false; return; }
    const m = inBlock ? /^(\S+)\s+(v\S+)/.exec(l) : /^require\s+(\S+)\s+(v\S+)/.exec(l);
    if (m) out.push({ ecosystem: "Go", name: m[1], version: m[2], path, direct: !/\/\/\s*indirect/.test(raw), line: i + 1 });
  });
  return out;
}

/** Names the project itself declares, per manifest directory, so a lockfile entry can be marked direct or transitive. */
async function declaredNpm(ctx: SecurityContext, dir: string): Promise<{ names: Set<string>; dev: Set<string>; text: string | null; path: string }> {
  const path = dir ? `${dir}/package.json` : "package.json";
  const text = ctx.files.includes(path) ? await ctx.read(path) : null;
  const names = new Set<string>(), dev = new Set<string>();
  if (text) {
    try {
      const j = JSON.parse(text) as Record<string, Record<string, string> | undefined>;
      for (const k of ["dependencies", "optionalDependencies", "peerDependencies"]) for (const n of Object.keys(j[k] ?? {})) names.add(n);
      for (const n of Object.keys(j.devDependencies ?? {})) { names.add(n); dev.add(n); }
    } catch { /* malformed manifest: everything reads as transitive */ }
  }
  return { names, dev, text, path };
}

export interface ParsedLockfiles { packages: Pkg[]; lockfiles: number; warnings: string[]; manifests: Map<string, { text: string | null; path: string }> }

/** Reads every lockfile we understand. Duplicates (the same name@version in several places) collapse to one. */
export async function parseLockfiles(ctx: SecurityContext): Promise<ParsedLockfiles> {
  const all: Pkg[] = [];
  const warnings: string[] = [];
  const manifests = new Map<string, { text: string | null; path: string }>();
  let lockfiles = 0;
  const dirOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");

  for (const path of ctx.files) {
    const base = path.split("/").pop()!;
    const dir = dirOf(path);
    if (dir.split("/").includes("node_modules")) continue;
    const isLock = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "Cargo.lock"].includes(base);
    const isOther = base === "go.mod" || /^requirements[^/]*\.txt$/.test(base);
    if (!isLock && !isOther) continue;
    const text = await ctx.read(path);
    if (text === null) { warnings.push(`${path} is too large to read and was skipped.`); continue; }
    lockfiles++;
    if (["package-lock.json", "pnpm-lock.yaml", "yarn.lock"].includes(base)) {
      const d = await declaredNpm(ctx, dir);
      manifests.set(dir, { text: d.text, path: d.path });
      const found = base === "package-lock.json" ? npmLock(text, path, d.names) : base === "pnpm-lock.yaml" ? pnpmLock(text, path, d.names) : yarnLock(text, path, d.names);
      for (const p of found) if (d.dev.has(p.name) && p.direct) p.dev = true;
      all.push(...found);
    } else if (base === "poetry.lock") all.push(...tomlPackages(text, path, "PyPI", new Set()));
    else if (base === "Cargo.lock") all.push(...tomlPackages(text, path, "crates.io", new Set()));
    else if (base === "go.mod") all.push(...goMod(text, path));
    else all.push(...requirements(text, path));
  }

  const seen = new Map<string, Pkg>();
  for (const p of all) {
    const k = `${p.ecosystem}\u0000${p.name}\u0000${p.version}`;
    const prev = seen.get(k);
    if (!prev) seen.set(k, p);
    else if (p.direct && !prev.direct) seen.set(k, { ...prev, direct: true });
  }
  let packages = [...seen.values()];
  if (packages.length > MAX_PACKAGES) { warnings.push(`Only the first ${MAX_PACKAGES} of ${packages.length} packages were checked.`); packages = packages.slice(0, MAX_PACKAGES); }
  return { packages, lockfiles, warnings, manifests };
}
