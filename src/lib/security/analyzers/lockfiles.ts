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
  /** 1-based line in `path`, when the format makes that easy */
  line?: number;
}

const MAX_PACKAGES = 5000;

/** `name@1.2.3` style keys (pnpm, yarn): the name may start with @scope/. */
const splitKey = (k: string): { name: string; version: string } | null => {
  const m = /^\/?(@?[^@\s/]+(?:\/[^@\s/]+)?)@(\d[^()\s_]*)/.exec(k) ?? /^\/?(@?[^@\s]+?)\/(\d[^()\s_/]*)$/.exec(k);
  return m ? { name: m[1], version: m[2] } : null;
};

function npmLock(text: string, path: string, directNames: Set<string>): Pkg[] {
  let j: { packages?: Record<string, { version?: string; dev?: boolean; link?: boolean }>; dependencies?: Record<string, { version?: string; dev?: boolean }> };
  try { j = JSON.parse(text); } catch { return []; }
  const out: Pkg[] = [];
  if (j.packages) {
    for (const [key, v] of Object.entries(j.packages)) {
      if (!key || v.link || !v.version) continue; // "" is the root project
      const name = key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
      if (name) out.push({ ecosystem: "npm", name, version: v.version, path, direct: directNames.has(name), dev: !!v.dev });
    }
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

function pnpmLock(text: string, path: string, directNames: Set<string>): Pkg[] {
  let y: { packages?: Record<string, unknown>; snapshots?: Record<string, unknown> };
  try { y = parseYaml(text); } catch { return []; }
  const out: Pkg[] = [];
  for (const key of Object.keys(y?.packages ?? y?.snapshots ?? {})) {
    const p = splitKey(key);
    if (p) out.push({ ecosystem: "npm", name: p.name, version: p.version, path, direct: directNames.has(p.name) });
  }
  return out;
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
