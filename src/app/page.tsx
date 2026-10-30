import type { Metadata } from "next";
import Link from "next/link";
import { Activity, GitBranch, ShieldCheck } from "lucide-react";
import { SiteFooter, SiteHeader } from "@/components/site/SiteChrome";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: `${SITE.product}: a live map of how your software is built and run`,
  description: "Point it at a GitHub repository and get a live, zoomable map of the system, whether it is healthy, and where it is at risk. Open source.",
};

/** A decorative miniature of the product: blocks coloured by health, one of them in trouble. Not data. */
function MiniMap() {
  const tone = { ok: "var(--color-nominal)", warn: "var(--color-degraded)", bad: "var(--color-failing)" };
  const node = (x: number, y: number, label: string, t: keyof typeof tone) => (
    <g key={label} transform={`translate(${x} ${y})`}>
      <rect width="128" height="52" rx="10" fill="var(--color-surface)" stroke={tone[t]} strokeOpacity={t === "ok" ? 0.4 : 0.9} />
      <circle cx="22" cy="26" r="8" fill="none" stroke={tone[t]} strokeWidth="2.5" />
      <text x="40" y="31" fill="var(--color-ink)" fontSize="13" fontWeight="600">{label}</text>
    </g>
  );
  return (
    <svg viewBox="0 0 520 250" role="img" aria-label="Illustration: a system drawn as connected blocks, each coloured by its health" className="w-full max-w-xl">
      <g stroke="var(--color-line)" strokeWidth="2" fill="none">
        <path d="M128 60 C170 60 170 125 212 125" /><path d="M128 190 C170 190 170 125 212 125" /><path d="M340 125 C380 125 380 60 392 60" /><path d="M340 125 C380 125 380 190 392 190" />
      </g>
      {node(0, 34, "Web app", "ok")}{node(0, 164, "CI pipeline", "bad")}{node(212, 99, "API", "warn")}{node(392, 34, "Database", "ok")}{node(392, 164, "Payments", "ok")}
    </svg>
  );
}

const STEPS = [
  { Icon: GitBranch, title: "Map it", body: "Paste a repository. We read its workflows, containers and code and draw how it is built and run, from the whole system down to a single file." },
  { Icon: Activity, title: "See its health", body: "Blocks glow by state: working, degrading or failing. Open a red one to find the exact failing step, and what depends on it." },
  { Icon: ShieldCheck, title: "Find its risks", body: "A security view colours the same map by risk: vulnerable dependencies, leaked keys and unsafe pipelines, each pinned to a file and line." },
];

export default function Home() {
  return (
    <>
      <SiteHeader />
      <main className="mx-auto w-full max-w-5xl flex-1 px-6">
        <section className="grid items-center gap-10 py-10 md:grid-cols-2 md:py-16">
          <div>
            <h1 className="text-4xl font-semibold leading-tight tracking-tight md:text-5xl">See how your software is built, shipped and running.</h1>
            <p className="mt-4 max-w-md text-ink-dim">
              {SITE.product} turns a GitHub repository into a live, zoomable map: what the system is made of, whether it is healthy right now, and where it is at risk.
            </p>
            <div className="mt-7 flex flex-wrap gap-3">
              <Link href="/demo" className="rounded-xl bg-accent px-5 py-2.5 text-sm font-medium text-void">Try the live demo</Link>
              <Link href="/scan" className="rounded-xl border border-line px-5 py-2.5 text-sm font-medium text-ink hover:border-accent/60">Map a public repository</Link>
              <Link href="/repos" className="rounded-xl border border-line px-5 py-2.5 text-sm font-medium text-ink hover:border-accent/60">Sign in with GitHub</Link>
            </div>
            <p className="mt-3 max-w-md text-xs leading-relaxed text-ink-faint">
              The demo and public repositories need no account. Signing in sends you to github.com to approve read-only access; this site never sees your GitHub password.
            </p>
          </div>
          <div className="flex justify-center"><MiniMap /></div>
        </section>

        <section aria-labelledby="how" className="py-6">
          <h2 id="how" className="text-lg font-semibold">How it works</h2>
          <ul className="mt-4 grid gap-4 md:grid-cols-3">
            {STEPS.map(({ Icon, title, body }) => (
              <li key={title} className="rounded-2xl border border-line bg-surface p-5">
                <Icon size={20} className="text-accent" aria-hidden />
                <h3 className="mt-3 font-medium">{title}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-ink-dim">{body}</p>
              </li>
            ))}
          </ul>
        </section>

        <section aria-labelledby="trust" className="mt-10 rounded-2xl border border-line bg-surface p-6">
          <h2 id="trust" className="text-lg font-semibold">Who runs this, and what it can do</h2>
          <ul className="mt-3 space-y-2 text-sm leading-relaxed text-ink-dim">
            <li><span className="text-ink">Operator:</span> built and run by <a className="underline underline-offset-2 hover:text-ink" href={SITE.operatorUrl} rel="noopener noreferrer">{SITE.operator}</a>. The <a className="underline underline-offset-2 hover:text-ink" href={SITE.source} rel="noopener noreferrer">source code is public</a>, so you can check every claim on this page.</li>
            <li><span className="text-ink">Access:</span> a GitHub App with read-only permissions (repository contents, workflows, deployments, checks and metadata). It cannot change your code.</li>
            <li><span className="text-ink">Your code:</span> downloaded to a temporary folder for analysis and deleted straight afterwards. We keep the map&apos;s structure and security findings (file names and line numbers), never your source code or a secret&apos;s value.</li>
            <li><span className="text-ink">Questions:</span> read <Link className="underline underline-offset-2 hover:text-ink" href="/about">About</Link> and the <Link className="underline underline-offset-2 hover:text-ink" href="/privacy">privacy notice</Link>, or <a className="underline underline-offset-2 hover:text-ink" href={SITE.issues} rel="noopener noreferrer">open an issue</a>.</li>
          </ul>
        </section>
      </main>
      <SiteFooter />
    </>
  );
}
