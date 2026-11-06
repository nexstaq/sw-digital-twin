"use client";

import { useCallback, useEffect, useState } from "react";
import { CalendarClock } from "lucide-react";
import type { Schedule } from "@/lib/security/types";

type Cadence = "off" | "daily" | "weekly";
const when = (t: number) => new Date(t).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

/** Opt-in automatic re-scans. Off by default; a maintainer turns it on, and can turn it off again at any time. */
export function ScheduledScans({ repo, onChanged }: { repo: string; onChanged: () => void }) {
  const [state, setState] = useState<{ schedule: Schedule | null; configured: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const q = encodeURIComponent(repo);

  const load = useCallback(async () => {
    const r = await fetch(`/api/security/schedule?repo=${q}`, { cache: "no-store" });
    if (r.ok) setState((await r.json()) as { schedule: Schedule | null; configured: boolean });
  }, [q]);
  useEffect(() => { void load(); }, [load]); // eslint-disable-line react-hooks/set-state-in-effect

  const set = async (cadence: Cadence) => {
    setBusy(true); setError(null);
    try {
      const r = await fetch("/api/security/schedule", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ repo, cadence }) });
      if (!r.ok) setError(((await r.json().catch(() => null)) as { error?: string } | null)?.error ?? `That failed (${r.status}).`);
      await load(); onChanged();
    } catch { setError("Could not reach the service."); } finally { setBusy(false); }
  };

  if (!state) return null;
  const s = state.schedule;
  return (
    <div className="mt-3 border-t border-line pt-3 text-[11px] leading-snug text-ink-dim" aria-label="Scheduled scans">
      <h4 className="flex items-center gap-1.5 font-medium text-ink"><CalendarClock size={12} aria-hidden /> Scheduled scans</h4>
      <p className="mt-1">Re-scan this repository automatically, and re-check any verified live site, so new advisories show up without you opening the page. Runs once a day at about 04:17 UTC when due.</p>
      {!state.configured && <p className="mt-1 text-degraded">Scheduling is not switched on for this deployment yet, so nothing will run.</p>}
      <label className="mt-2 flex items-center gap-2">
        <span>Re-scan</span>
        <select value={s?.cadence ?? "off"} disabled={busy} onChange={(e) => void set(e.target.value as Cadence)} aria-label="Scan schedule"
          className="rounded-md border border-line bg-void px-2 py-1 text-[11px] text-ink outline-none focus:border-accent">
          <option value="off">Off</option>
          <option value="daily">Every day</option>
          <option value="weekly">Every week</option>
        </select>
      </label>
      {s?.lastRunAt && <p className={`mt-1.5 ${s.lastStatus === "failed" ? "text-failing" : "text-ink-faint"}`}>Last run {when(s.lastRunAt)}: {s.lastStatus === "failed" ? "failed" : "ok"}.{s.lastMessage ? ` ${s.lastMessage}` : ""}</p>}
      {s && !s.lastRunAt && <p className="mt-1.5 text-ink-faint">Enabled by {s.enabledBy}. It has not run yet.</p>}
      {error && <p role="alert" className="mt-1.5 text-failing">{error}</p>}
    </div>
  );
}
