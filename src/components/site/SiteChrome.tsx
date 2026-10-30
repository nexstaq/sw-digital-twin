import Link from "next/link";
import { SITE } from "@/lib/site";

/** Plain, readable identity on every public page: who this is, where the code is, how to reach the operator. */
export function SiteHeader() {
  return (
    <header className="mx-auto flex w-full max-w-5xl flex-wrap items-center justify-between gap-4 px-6 py-5">
      <Link href="/" className="flex items-center gap-2.5">
        <span className="grid h-8 w-8 place-items-center rounded-lg bg-accent/15 text-accent" aria-hidden>◎</span>
        <span className="text-sm font-semibold">{SITE.product}</span>
      </Link>
      <nav aria-label="Main" className="flex flex-wrap items-center gap-x-5 gap-y-1 text-sm text-ink-dim">
        <Link href="/demo" className="hover:text-ink">Demo</Link>
        <Link href="/repos" className="hover:text-ink">Your repositories</Link>
        <Link href="/about" className="hover:text-ink">About</Link>
        <Link href="/privacy" className="hover:text-ink">Privacy</Link>
        <a href={SITE.source} className="hover:text-ink" rel="noopener noreferrer">Source code</a>
      </nav>
    </header>
  );
}

export function SiteFooter() {
  return (
    <footer className="mx-auto mt-16 w-full max-w-5xl border-t border-line px-6 py-8 text-xs leading-relaxed text-ink-faint">
      <p>
        {SITE.product} is built and run by <a href={SITE.operatorUrl} className="text-ink-dim underline-offset-2 hover:underline" rel="noopener noreferrer">{SITE.operator}</a> and is open source.
        It is not affiliated with, endorsed by or sponsored by GitHub, Inc. “GitHub” is a trademark of GitHub, Inc.
      </p>
      <nav aria-label="Footer" className="mt-3 flex flex-wrap gap-x-5 gap-y-1">
        <Link href="/about" className="hover:text-ink-dim">About</Link>
        <Link href="/privacy" className="hover:text-ink-dim">Privacy</Link>
        <a href={SITE.source} className="hover:text-ink-dim" rel="noopener noreferrer">Source code</a>
        <a href={SITE.issues} className="hover:text-ink-dim" rel="noopener noreferrer">Contact and issues</a>
        <a href={SITE.securityReport} className="hover:text-ink-dim" rel="noopener noreferrer">Report a security problem</a>
        <a href="/.well-known/security.txt" className="hover:text-ink-dim">security.txt</a>
      </nav>
    </footer>
  );
}
