import type { Status } from "./status";

declare const TWIN_ORIGIN: string; // injected by build.mjs

const TTL_OK = 60_000; // a real verdict is cheap to reuse
const TTL_OTHER = 5_000; // "sign in", "not mapped"… must clear quickly, or signing in would look broken for a minute
const cache = new Map<string, { at: number; status: Status }>();

/**
 * Asks Mission Control for one repo's verdict. This worker is the only thing that talks to the network: it holds the host
 * permission, so the page's CORS and CSP never apply, and the page script never sees a URL, cookie or token.
 * Private repos work through the browser's own signed-in session with the app (credentials: "include").
 */
async function fetchStatus(repo: string): Promise<Status> {
  const hit = cache.get(repo);
  if (hit && Date.now() - hit.at < (hit.status.state === "ok" ? TTL_OK : TTL_OTHER)) return hit.status;
  let status: Status;
  try {
    const res = await fetch(`${TWIN_ORIGIN}/api/verdict?repo=${encodeURIComponent(repo)}`, { credentials: "include", signal: AbortSignal.timeout(8000) });
    if (res.status === 401 || res.status === 403) status = { state: "signin" };
    else if (!res.ok) status = { state: "unavailable" };
    else {
      const d = (await res.json()) as { state?: string; word?: string; tone?: string; why?: string };
      status = d.state === "ok" && d.word && ["nominal", "degraded", "failing", "unknown"].includes(d.tone ?? "")
        ? { state: "ok", word: d.word, tone: d.tone as "nominal", why: d.why ?? "" }
        : d.state === "unmapped" ? { state: "unmapped" } : { state: "unavailable" };
    }
  } catch { return { state: "offline" }; } // not cached, so the next page view retries
  if (cache.size > 200) cache.clear();
  cache.set(repo, { at: Date.now(), status });
  return status;
}

chrome.runtime.onMessage.addListener((msg: unknown, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false; // only our own content script
  const m = msg as { type?: string; repo?: string };
  if (m?.type !== "status" || typeof m.repo !== "string" || !/^[\w.-]{1,39}\/[\w.-]{1,100}$/.test(m.repo)) return false;
  void fetchStatus(m.repo).then(sendResponse);
  return true; // async response
});
