"use client";

import { useEffect, useState } from "react";
import type { Activity, DeployMarker } from "@/lib/graph/types";
import { Play } from "lucide-react";
import type { Incident } from "@/lib/health/incident";
import { useTwin } from "@/lib/store";

const SPAN = 48; // hours shown

const clock = (ms: number) => { const s = Math.max(0, Math.floor(ms / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; };

/** Countdown-style readout of what is in flight: a ticking timer while something runs. */
function ActivityChip({ a }: { a: Activity }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { if (!a.running) return; const t = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(t); }, [a.running]);
  if (!a.running && !a.queued) return null;
  return (
    <div className="flex shrink-0 items-center gap-2 rounded-md border border-accent/40 bg-accent/10 px-2.5 py-1 font-mono text-xs text-accent" role="status">
      {a.running > 0 && <span className="h-2 w-2 animate-pulse rounded-full bg-accent motion-reduce:animate-none" aria-hidden />}
      <span>{a.running > 0 ? `${a.running} running${a.since ? ` · T+${clock(now - Date.parse(a.since))}` : ""}` : ""}{a.running > 0 && a.queued > 0 ? " · " : ""}{a.queued > 0 ? `${a.queued} queued` : ""}</span>
    </div>
  );
}

const ago = (h: number) => (h < 1 ? `${Math.max(1, Math.round(h * 60))}m` : `${Math.round(h * 10) / 10}h`);

export function TimelineScrubber({ deploys, activity, incident, anchor }: { deploys: DeployMarker[]; activity?: Activity; incident?: Incident | null; anchor?: number }) {
  const scrub = useTwin((s) => s.scrub);
  const setScrub = useTwin((s) => s.setScrub);
  const pct = (h: number) => `${((SPAN - h) / SPAN) * 100}%`;
  const replay = useTwin((s) => s.replay);
  const setReplay = useTwin((s) => s.setReplay);
  const hoursAgo = (ts: number) => (anchor ? Math.max(0, (anchor - ts) / 3_600_000) : 0);
  const band = incident && anchor ? { from: hoursAgo(incident.endTs ?? anchor), to: hoursAgo(incident.startTs) } : null;
  const startReplay = () => {
    if (!incident || !anchor) return;
    setScrub(hoursAgo(incident.startTs - 20 * 60_000));
    setReplay({ playing: true, speed: 1 });
  };
  const last = deploys.length ? deploys.reduce((a, d) => (d.hoursAgo < a.hoursAgo ? d : a)) : null;

  return (
    <div className="flex items-center gap-4 border-t border-line bg-surface/80 px-4 py-2.5 backdrop-blur">
      <div className="w-52 shrink-0 text-xs leading-tight">
        <div className="font-mono text-ink">{scrub === 0 ? "LIVE" : `T-${ago(scrub)}${anchor ? ` · ${new Date(anchor - scrub * 3_600_000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}` : ""}`}</div>
        <div className="text-ink-dim">{last ? `Last deploy ${last.ok ? "" : "FAILED "}${last.label} · ${last.hoursAgo < 1 ? `${Math.max(1, Math.round(last.hoursAgo * 60))}m` : last.hoursAgo < 48 ? `${Math.round(last.hoursAgo)}h` : `${Math.round(last.hoursAgo / 24)}d`} ago` : "No deploy history yet"}</div>
      </div>
      <div className="relative h-9 flex-1">
        <div className="absolute inset-x-0 top-1/2 h-px bg-line" />
        {band && <div className="absolute top-1/2 h-2 -translate-y-1/2 rounded-sm bg-failing/30 ring-1 ring-failing/50" style={{ left: pct(Math.min(band.to, SPAN)), right: `${100 - ((SPAN - band.from) / SPAN) * 100}%` }} title="Incident" aria-hidden />}
        {deploys.map((d, i) => (
          <div
            key={`${d.label}-${i}`}
            className="absolute top-1/2 -translate-x-1/2 -translate-y-1/2"
            style={{ left: pct(d.hoursAgo) }}
            title={`Deploy ${d.label}`}
          >
            <div className={`h-3 w-3 rotate-45 border ${d.ok ? "border-nominal bg-nominal/30" : "border-failing bg-failing/40"}`} />
          </div>
        ))}
        <input
          type="range"
          aria-label="Time scrubber"
          min={0}
          max={SPAN}
          step={0.5}
          value={SPAN - scrub}
          onChange={(e) => setScrub(SPAN - Number(e.target.value))}
          className="absolute inset-0 h-full w-full cursor-pointer appearance-none bg-transparent accent-accent"
        />
      </div>
      {incident && anchor && !replay && (
        <button onClick={startReplay} className="flex shrink-0 items-center gap-1.5 rounded-md border border-failing/50 bg-failing/10 px-2.5 py-1 text-xs text-failing hover:bg-failing/20">
          <Play size={12} aria-hidden /> Replay incident <span className="hidden font-mono text-[11px] text-ink-dim md:inline">{ago(hoursAgo(incident.startTs))} ago</span>
        </button>
      )}
      {activity && <ActivityChip a={activity} />}
      <button
        onClick={() => setScrub(0)}
        disabled={scrub === 0}
        className="rounded-md border border-line px-2.5 py-1 font-mono text-xs text-ink-dim enabled:hover:text-ink disabled:opacity-40"
      >
        ● LIVE
      </button>
    </div>
  );
}
