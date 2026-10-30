"use client";

import dynamic from "next/dynamic";

// The demo is anchored to "now", which a prerender must not bake in, so it renders in the browser only.
const IncidentDemo = dynamic(() => import("./IncidentDemo").then((m) => m.IncidentDemo), {
  ssr: false,
  loading: () => <div className="grid h-dvh place-items-center text-sm text-ink-dim">Loading the incident…</div>,
});

export function IncidentDemoClient() {
  return <IncidentDemo />;
}
