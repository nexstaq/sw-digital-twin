import { cloneRepo, gitHead, parseRepo } from "@/lib/ingest/repo";
import { persist } from "@/lib/persist";
import { combine } from "./external";
import { fetchGithubAlerts } from "./github-alerts";
import { analyzeDirectory } from "./scan";
import { withHistory } from "./trend";
import type { FindingSet } from "./types";

/**
 * One full security scan of a repo's default branch, stored as the repo's latest findings. Shared by the "Scan" button and the
 * scheduled re-scan so both do exactly the same thing. The caller has already decided the token is allowed to read this repo.
 */
export async function scanAndStore(repo: string, token: string | undefined, signal?: AbortSignal): Promise<FindingSet> {
  let checkout: Awaited<ReturnType<typeof cloneRepo>> | undefined;
  try {
    checkout = await cloneRepo(parseRepo(repo), signal, token);
    const sha = (checkout.head ?? (await gitHead(checkout.dir)))?.sha ?? checkout.sha;
    // the saved map tells us which files are request handlers, for the exposure check behind attack paths
    const store = persist();
    const latest = (await store.listSnapshots(repo)).at(-1);
    const map = latest && (await store.getSnapshot(repo, latest.sha));
    const endpointFiles = map ? [...new Set(map.graph.nodes.filter((n) => n.kind === "endpoint").flatMap((n) => n.evidence.map((e) => e.path)))] : [];
    const previous = await store.getFindings(repo);
    const fresh = await analyzeDirectory(checkout.dir, repo, sha, {}, { endpointFiles });
    // GitHub's own alerts (Dependabot, code scanning, secret scanning), each reporting whether it worked; reports imported from CI are kept
    const alerts = await fetchGithubAlerts(repo, token, fresh.findings);
    const set = withHistory(combine(fresh, previous, alerts), previous);
    await store.putFindings(repo, set);
    return set;
  } finally {
    await checkout?.cleanup();
  }
}
