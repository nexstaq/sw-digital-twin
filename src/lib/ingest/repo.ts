import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { lstat, mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Readable } from "node:stream";
import { createGunzip } from "node:zlib";
import { extractTar } from "./tarball";

const run = promisify(execFile);

export interface RepoRef {
  owner: string;
  name: string;
  url: string;
  ref?: string;
}

/**
 * Accepts `owner/repo` or a github.com https URL. Anything else is rejected:
 * we shell out to git, so the URL must never be attacker-shaped.
 */
export function parseRepo(input: string, ref?: string): RepoRef {
  const trimmed = input.trim();
  const m =
    /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/.exec(trimmed) ??
    /^([\w.-]+)\/([\w.-]+)$/.exec(trimmed);
  if (!m) throw new Error("Enter a GitHub repo as owner/repo or https://github.com/owner/repo");
  const [, owner, name] = m;
  if (owner.startsWith(".") || name.startsWith(".")) throw new Error("Invalid repository name");
  if (ref !== undefined && (!/^[\w][\w./-]{0,99}$/.test(ref) || ref.includes(".."))) throw new Error("Invalid ref");
  return { owner, name, url: `https://github.com/${owner}/${name}.git`, ref };
}

const GIT_ENV = {
  PATH: process.env.PATH ?? "",
  HOME: tmpdir(),
  GIT_TERMINAL_PROMPT: "0",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
} as unknown as NodeJS.ProcessEnv; // deliberately minimal: no inherited secrets or git config

export interface Checkout {
  dir: string;
  sha: string;
  /** set when the checkout has no .git (tarball path), so the caller need not ask git */
  head?: { sha: string; committedAt: string };
  cleanup(): Promise<void>;
}

/**
 * Git config that authenticates ONE host, passed through the environment (GIT_CONFIG_COUNT/KEY/VALUE). The token is
 * therefore never in argv (visible in `ps`), never in the clone URL, and never written to .git/config.
 */
export function gitAuthEnv(url: string, token: string): Record<string, string> {
  const origin = new URL(url).origin;
  return {
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: `http.${origin}/.extraheader`,
    GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${Buffer.from(`x-access-token:${token}`).toString("base64")}`,
  };
}

let gitAvailable: Promise<boolean> | undefined;
/** Vercel's runtime has no git binary; there we download GitHub's tarball instead. TWIN_FETCH=tarball forces that path. */
function hasGit(): Promise<boolean> {
  if (process.env.TWIN_FETCH === "tarball") return Promise.resolve(false);
  return (gitAvailable ??= run("git", ["--version"], { env: GIT_ENV, timeout: 5_000 }).then(() => true, () => false));
}

const apiBase = () => (process.env.GITHUB_API_URL ?? "https://api.github.com").replace(/\/$/, "");

/** Same result as cloneRepo without git: GitHub's tarball of one ref, unpacked by tarball.ts. No history, so no churn. */
export async function fetchRepo(repo: RepoRef, signal?: AbortSignal, token?: string): Promise<Checkout> {
  const dir = await mkdtemp(path.join(tmpdir(), "twin-"));
  const cleanup = () => rm(dir, { recursive: true, force: true });
  const headers: Record<string, string> = { accept: "application/vnd.github+json", "user-agent": "sw-digital-twin", "x-github-api-version": "2022-11-28" };
  if (token) headers.authorization = `Bearer ${token}`;
  const sig = AbortSignal.any([AbortSignal.timeout(90_000), ...(signal ? [signal] : [])]);
  try {
    const res = await fetch(`${apiBase()}/repos/${repo.owner}/${repo.name}/tarball${repo.ref ? `/${encodeURIComponent(repo.ref)}` : ""}`, { headers, signal: sig, redirect: "follow" });
    if (res.status === 404 || res.status === 401 || res.status === 403) throw new Error("not found");
    if (!res.ok || !res.body) throw new Error(`GitHub answered ${res.status}`);
    const gunzip = Readable.fromWeb(res.body as never).pipe(createGunzip());
    const { sha } = await extractTar(gunzip, dir, {
      maxBytes: 400 << 20, maxFiles: 100_000, maxFileBytes: MAX_FILE_BYTES, skipDir: (n) => SKIP_DIRS.has(n),
    });
    if (!sha) throw new Error("GitHub's archive did not say which commit it is");
    let committedAt = new Date().toISOString();
    try { // optional: the real commit time, so a stored snapshot sorts correctly
      const c = await fetch(`${apiBase()}/repos/${repo.owner}/${repo.name}/commits/${sha}`, { headers, signal: sig });
      const when = c.ok ? ((await c.json()) as { commit?: { committer?: { date?: string } } }).commit?.committer?.date : undefined;
      if (when) committedAt = when;
    } catch { /* keep "now" */ }
    return { dir, sha, head: { sha, committedAt }, cleanup };
  } catch (e) {
    await cleanup();
    const msg = e instanceof Error ? e.message : String(e);
    if (/not found/i.test(msg)) throw new Error(cloneFailure(!!token));
    if (/too large/i.test(msg)) throw new Error(msg);
    throw new Error("Download failed or timed out");
  }
}

const cloneFailure = (authed: boolean) => authed
  ? "GitHub refused the clone. Check that the GitHub App is installed on this repository with read access to its contents."
  : "Could not clone that repository. It may be private (sign in with GitHub and install the app) or the name is wrong.";

/** Shallow clone into a private temp dir. Never executes anything from the repo. `token` is for private repos only. */
export async function cloneRepo(repo: RepoRef, signal?: AbortSignal, token?: string): Promise<Checkout> {
  if (!(await hasGit())) return fetchRepo(repo, signal, token);
  const dir = await mkdtemp(path.join(tmpdir(), "twin-"));
  const cleanup = () => rm(dir, { recursive: true, force: true });
  try {
    const args = [
      "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-c", "core.symlinks=false",
      "clone", "--depth", "100", "--single-branch", "--no-tags",
      ...(repo.ref ? ["--branch", repo.ref] : []),
      "--", repo.url, dir,
    ];
    const cloneEnv = token ? ({ ...GIT_ENV, ...gitAuthEnv(repo.url, token) } as unknown as NodeJS.ProcessEnv) : GIT_ENV;
    await run("git", args, { env: cloneEnv, timeout: 90_000, signal, maxBuffer: 1 << 20 });
    const { stdout } = await run("git", ["-C", dir, "rev-parse", "HEAD"], { env: GIT_ENV, timeout: 10_000 });
    return { dir, sha: stdout.trim(), cleanup };
  } catch (e) {
    await cleanup();
    const msg = e instanceof Error ? e.message : String(e);
    if (/not found|Authentication|could not read/i.test(msg)) {
      throw new Error(cloneFailure(!!token));
    }
    throw new Error("Clone failed or timed out");
  }
}

const SKIP_DIRS = new Set([
  ".git", "node_modules", "dist", "build", ".next", ".turbo", "vendor", "target", "__pycache__",
  ".venv", "venv", ".cache", "coverage", ".idea", ".vscode", "out", ".terraform", "Pods",
]);
export const MAX_FILES = 20_000;
export const MAX_FILE_BYTES = 512 * 1024;

/** Lists readable files. Symlinks are skipped so a repo can never point us outside its checkout. */
export async function listFiles(root: string): Promise<string[]> {
  const out: string[] = [];
  async function walk(rel: string) {
    if (out.length >= MAX_FILES) return;
    const entries = await readdir(path.join(root, rel), { withFileTypes: true });
    for (const e of entries) {
      if (e.isSymbolicLink()) continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) await walk(r);
      } else if (e.isFile()) {
        out.push(r);
        if (out.length >= MAX_FILES) return;
      }
    }
  }
  await walk("");
  return out.sort();
}

export function makeReader(root: string) {
  const base = path.resolve(root) + path.sep;
  return async (rel: string): Promise<string | null> => {
    const abs = path.resolve(root, rel);
    if (!abs.startsWith(base)) return null;
    try {
      const st = await lstat(abs);
      if (!st.isFile() || st.size > MAX_FILE_BYTES) return null;
      return await readFile(abs, "utf8");
    } catch {
      return null;
    }
  };
}

/** commits touching each file, from the (shallow) history we cloned */
export async function gitChurn(dir: string): Promise<Map<string, number>> {
  const counts = new Map<string, number>();
  try {
    const { stdout } = await run("git", ["-C", dir, "log", "--name-only", "--pretty=format:", "-n", "100"], {
      env: GIT_ENV, timeout: 20_000, maxBuffer: 8 << 20,
    });
    for (const line of stdout.split("\n")) if (line) counts.set(line, (counts.get(line) ?? 0) + 1);
  } catch { /* history is optional */ }
  return counts;
}

/** The commit that was analysed, so a scan can be stored as "the map at this commit". */
export async function gitHead(dir: string): Promise<{ sha: string; committedAt: string } | undefined> {
  try {
    const { stdout } = await run("git", ["-C", dir, "log", "-1", "--format=%H%x09%cI"], { env: GIT_ENV, timeout: 10_000 });
    const [sha, committedAt] = stdout.trim().split("\t");
    return /^[0-9a-f]{40}$/.test(sha ?? "") && committedAt ? { sha, committedAt } : undefined;
  } catch { return undefined; }
}
