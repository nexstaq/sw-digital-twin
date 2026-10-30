import type { Metadata } from "next";
import { Suspense } from "react";
import { SharedView } from "@/components/twin/SharedView";

// a share link is a bearer secret: keep it out of search engines
export const metadata: Metadata = { title: "Shared map", robots: { index: false, follow: false }, referrer: "no-referrer" };

async function Resolve({ params }: { params: Promise<{ owner: string; repo: string; secret: string }> }) {
  const { owner, repo, secret } = await params;
  return <SharedView owner={owner} repo={repo} secret={secret} />;
}

export default function Page({ params }: { params: Promise<{ owner: string; repo: string; secret: string }> }) {
  return <Suspense fallback={<main className="grid min-h-dvh place-items-center text-ink-dim">Opening shared map…</main>}><Resolve params={params} /></Suspense>;
}
