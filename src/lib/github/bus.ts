/**
 * In-process "something changed for this repo" bus. Webhooks poke it; SSE streams wake on it and re-fetch.
 * It is per server instance. Across instances, streams still refresh on their poll interval, so it degrades to
 * "a few seconds late", never "wrong". A shared queue (Vercel Queues / Redis) can replace it behind the same API.
 */
type Listener = () => void;
const g = globalThis as unknown as { __twinBus?: Map<string, Set<Listener>> };
const listeners = (g.__twinBus ??= new Map());

export function poke(repo: string) {
  for (const fn of listeners.get(repo.toLowerCase()) ?? []) fn();
}

/** Resolves on the next poke for `repo`, or when `signal` aborts. */
export function nextPoke(repo: string, signal: AbortSignal): Promise<void> {
  const key = repo.toLowerCase();
  return new Promise((resolve) => {
    const set = listeners.get(key) ?? new Set<Listener>();
    listeners.set(key, set);
    const done = () => { set.delete(done); if (!set.size) listeners.delete(key); signal.removeEventListener("abort", done); resolve(); };
    set.add(done);
    signal.addEventListener("abort", done);
  });
}
