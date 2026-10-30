import type { SignalSet } from "@/lib/health/signals";
import { fetchSignals, GitHubError, type FetchOpts } from "./api";
import { collect } from "@/lib/connectors/collect";
import { tokenFor } from "./app";

const TTL = 15_000;
const PUBLIC_TTL = 10 * 60_000;
type Entry = { at: number; value?: SignalSet; pending?: Promise<SignalSet> };
const g = globalThis as unknown as { __twinSignals?: Map<string, Entry>; __twinPublic?: Map<string, { at: number; ok: boolean }> };
const cache = (g.__twinSignals ??= new Map());
const publicCache = (g.__twinPublic ??= new Map());

/**
 * Anonymous viewers may only see public repositories. We check that WITHOUT credentials so an App or shared token can never
 * be used to reveal a private repo to someone who is not signed in.
 */
export async function isPublicRepo(repo: string, f: typeof fetch = fetch): Promise<boolean> {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo) || repo.includes("..")) return false; // never build an API path from arbitrary input
  const hit = publicCache.get(repo);
  if (hit && Date.now() - hit.at < PUBLIC_TTL) return hit.ok;
  try {
    await fetchSignalsHead(repo, f);
    publicCache.set(repo, { at: Date.now(), ok: true });
    return true;
  } catch (e) {
    if (e instanceof GitHubError && e.status === 404) { publicCache.set(repo, { at: Date.now(), ok: false }); return false; }
    throw e; // rate limited etc.: not a verdict on the repo
  }
}

async function fetchSignalsHead(repo: string, f: typeof fetch) {
  const base = (process.env.GITHUB_API_URL ?? "https://api.github.com").replace(/\/$/, "");
  const res = await f(`${base}/repos/${repo}`, { headers: { accept: "application/vnd.github+json", "user-agent": "sw-digital-twin" }, cache: "no-store" });
  if (res.status === 404) throw new GitHubError("not found", 404);
  if (res.status === 429 || (res.status === 403 && res.headers.get("x-ratelimit-remaining") === "0")) {
    throw new GitHubError("GitHub rate limit reached. Set GITHUB_TOKEN or install the GitHub App for a higher limit.", 429, Number(res.headers.get("x-ratelimit-reset")) * 1000 || undefined);
  }
  if (!res.ok) throw new GitHubError(`GitHub returned ${res.status}.`, res.status);
}

/** Shared per instance: many viewers of one repo cost one GitHub fetch per TTL. `force` (a webhook fired) skips the TTL. */
export async function getSignals(repo: string, o: { force?: boolean; fetch?: typeof fetch; token?: string } = {}): Promise<SignalSet> {
  const key = repo.toLowerCase();
  const e = cache.get(key);
  if (e?.pending) return e.pending;
  if (!o.force && e?.value && Date.now() - e.at < TTL) return e.value;

  const opts: FetchOpts = { fetch: o.fetch, token: o.token ?? (await tokenFor(key)) };
  const pending = Promise.all([fetchSignals(key, opts), collect(key, { force: o.force, fetch: o.fetch })]).then(
    ([gh, extra]) => {
      // runtime telemetry and non-GitHub deploys (Vercel) join the same signal set the engine already understands
      const value: SignalSet = { ...gh, deploys: [...gh.deploys, ...extra.deploys], runtime: extra.runtime };
      cache.set(key, { at: Date.now(), value });
      return value;
    },
    (err) => { cache.set(key, { at: e?.at ?? 0, value: e?.value }); throw err; },
  );
  cache.set(key, { at: e?.at ?? 0, value: e?.value, pending });
  return pending;
}
