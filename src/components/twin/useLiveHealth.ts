"use client";

import { useEffect, useState } from "react";
import type { SignalSet } from "@/lib/health/signals";

export type LiveState =
  | { kind: "connecting" }
  | { kind: "live"; at: number }
  | { kind: "retrying"; message: string }
  | { kind: "unavailable"; message: string };

type Msg =
  | { type: "signals"; signals: SignalSet }
  | { type: "tick"; fetchedAt: number }
  | { type: "error"; message: string; fatal?: boolean };

/** Subscribes to /api/health/stream and returns the latest signals. Turn them into a graph with `useHealthView`. */
export function useLiveHealth(enabled: boolean, repo: string): { signals: SignalSet | null; live: LiveState } {
  const [signals, setSignals] = useState<SignalSet | null>(null);
  const [live, setLive] = useState<LiveState>({ kind: "connecting" });

  useEffect(() => {
    if (!enabled) return;
    const url = `/api/health/stream?repo=${encodeURIComponent(repo)}`;
    let es: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let gone = false;
    let tries = 0;

    const open = () => {
      es = new EventSource(url);
      es.onmessage = (m) => {
        tries = 0;
        const ev = JSON.parse(m.data) as Msg;
        if (ev.type === "signals") { setSignals(ev.signals); setLive({ kind: "live", at: ev.signals.fetchedAt }); }
        else if (ev.type === "tick") setLive({ kind: "live", at: ev.fetchedAt });
        else if (ev.fatal) { setLive({ kind: "unavailable", message: ev.message }); es?.close(); }
        else setLive({ kind: "retrying", message: ev.message });
      };
      // The server ends sessions periodically and EventSource reconnects by itself. It only gives up (CLOSED) on a
      // non-200 reply and hides why, so ask once for the reason and retry unless the answer is final.
      es.onerror = () => {
        if (es?.readyState !== EventSource.CLOSED) return;
        es.close();
        void why().then((reason) => {
          if (gone) return;
          if (reason.fatal) { setLive({ kind: "unavailable", message: reason.message }); return; }
          setLive({ kind: "retrying", message: reason.message });
          timer = setTimeout(open, Math.min(30_000, 2_000 * 2 ** tries++));
        });
      };
    };

    const why = async (): Promise<{ fatal: boolean; message: string }> => {
      try {
        const r = await fetch(url, { headers: { accept: "text/event-stream" } });
        const text = r.body ? await readFirst(r) : "";
        const ev = text ? (JSON.parse(text) as Msg) : null;
        if (ev && ev.type === "error") return { fatal: !!ev.fatal || r.status === 401 || r.status === 403 || r.status === 404, message: ev.message };
        return { fatal: false, message: `Reconnecting (HTTP ${r.status})…` };
      } catch { return { fatal: false, message: "Network hiccup. Reconnecting…" }; }
    };

    open();
    return () => { gone = true; clearTimeout(timer); es?.close(); };
  }, [enabled, repo]);

  return { signals, live };
}

/** First `data:` line of an event stream, then hang up. */
async function readFirst(r: Response): Promise<string> {
  const reader = r.body!.getReader();
  const dec = new TextDecoder();
  let buf = "";
  try {
    while (!buf.includes("\n\n")) { const { done, value } = await reader.read(); if (done) break; buf += dec.decode(value, { stream: true }); }
  } finally { void reader.cancel(); }
  return buf.split("\n").find((l) => l.startsWith("data:"))?.slice(5).trim() ?? "";
}
