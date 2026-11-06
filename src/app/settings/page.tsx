import { Suspense } from "react";
import { AccessSettings } from "@/components/twin/AccessSettings";

export const metadata = { title: "Access settings · Mission Control" };

export default function SettingsPage() {
  return <Suspense fallback={<main className="grid min-h-dvh place-items-center text-ink-dim">Loading…</main>}><AccessSettings /></Suspense>;
}
