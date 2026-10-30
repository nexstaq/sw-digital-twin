import type { DetectorContext } from "./types";

export const slug = (s: string) =>
  s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "x";

export const dirOf = (p: string) => (p.includes("/") ? p.slice(0, p.lastIndexOf("/")) : "");
export const baseOf = (p: string) => p.slice(p.lastIndexOf("/") + 1);
export const pkgId = (dir: string) => `pkg:${dir || "."}`;

/** 1-based line of the first occurrence of `needle`, or undefined */
export function lineOf(text: string, needle: string | RegExp): number | undefined {
  const i = typeof needle === "string" ? text.indexOf(needle) : text.search(needle);
  return i < 0 ? undefined : text.slice(0, i).split("\n").length;
}

export const lines = (a?: number, b?: number) => (a ? (b && b !== a ? `${a}-${b}` : `${a}`) : undefined);

const MANIFESTS = new Set(["package.json", "pyproject.toml", "requirements.txt", "go.mod", "Cargo.toml", "pom.xml", "Gemfile", "build.gradle"]);

/** Directories that contain a manifest, i.e. candidate packages/services. */
export function manifestDirs(files: string[]): string[] {
  const dirs = new Set<string>();
  for (const f of files) if (MANIFESTS.has(f.slice(f.lastIndexOf("/") + 1))) dirs.add(dirOf(f));
  return [...dirs].sort();
}

/** Deepest manifest dir containing `file` ("" = repo root). */
export function owningDir(file: string, dirs: string[]): string | undefined {
  let best: string | undefined;
  for (const d of dirs) {
    if ((d === "" || file.startsWith(d + "/")) && (best === undefined || d.length > best.length)) best = d;
  }
  return best;
}

export async function readJson<T = unknown>(ctx: DetectorContext, path: string): Promise<T | null> {
  const t = await ctx.read(path);
  if (t == null) return null;
  try { return JSON.parse(t) as T; } catch { return null; }
}

export function globToRegExp(glob: string): RegExp {
  let g = glob.trim();
  const anchored = g.startsWith("/");
  if (anchored) g = g.slice(1);
  const dirOnly = g.endsWith("/");
  if (dirOnly) g = g.slice(0, -1);
  const body = g
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "\u0000")
    .replace(/\*/g, "[^/]*")
    .replace(/\u0000/g, ".*");
  const prefix = anchored || g.includes("/") ? "^" : "^(?:.*/)?";
  return new RegExp(`${prefix}${body}${dirOnly || !/\.[\w]+$/.test(g) ? "(?:/.*)?" : ""}$`);
}
