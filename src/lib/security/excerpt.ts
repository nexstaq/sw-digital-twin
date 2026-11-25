import type { Excerpt } from "@/lib/sim/whitebox/source";
import { redactLine } from "./analyzers/secrets";

const MAX_BYTES = 1_000_000;
const apiBase = () => (process.env.GITHUB_API_URL ?? "https://api.github.com").replace(/\/$/, "");
// brackets and parentheses are ordinary in framework file names (Next.js: app/api/orders/[id]/route.ts, app/(shop)/page.tsx); ".." and a leading "/" are still refused below
const SAFE_PATH = /^[\w@.+\-/ \[\]()]{1,300}$/;

/**
 * A few lines of one file at one commit, read from GitHub with the caller's own access. Same rules as the snippet route: only files a
 * stored finding points at (the caller checks), secrets redacted on the way in, nothing stored, and it never throws: any failure is
 * "no excerpt", which the simulation treats as "source not read".
 */
export async function fetchExcerpt(repo: string, sha: string, path: string, line: number | undefined, token: string | undefined, o: { span?: number; signal?: AbortSignal } = {}): Promise<Excerpt | null> {
  if (!line || !Number.isInteger(line) || line < 1 || line > 1_000_000) return null;
  if (!SAFE_PATH.test(path) || path.startsWith("/") || path.split("/").some((s) => s === ".." || s === ".")) return null;
  try {
    const res = await fetch(`${apiBase()}/repos/${repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${encodeURIComponent(sha)}`, {
      headers: { accept: "application/vnd.github.raw+json", "user-agent": "sw-digital-twin", "x-github-api-version": "2022-11-28", ...(token ? { authorization: `Bearer ${token}` } : {}) },
      cache: "no-store", signal: o.signal,
    });
    if (!res.ok) return null;
    const all = (await res.text()).slice(0, MAX_BYTES).split("\n");
    if (line > all.length) return null;
    const span = o.span ?? 12;
    const start = Math.max(1, line - span);
    return { path, startLine: start, lines: all.slice(start - 1, Math.min(all.length, line + span)).map((t) => redactLine(t.slice(0, 300))) };
  } catch { return null; }
}
