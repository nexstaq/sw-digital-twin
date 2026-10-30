import type { Metadata } from "next";
import { SiteFooter, SiteHeader } from "@/components/site/SiteChrome";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: `Privacy · ${SITE.product}`,
  description: `Exactly what ${SITE.product} collects, stores, shares and for how long.`,
};

const H = ({ children }: { children: React.ReactNode }) => <h2 className="mt-10 text-lg font-semibold">{children}</h2>;
const P = ({ children }: { children: React.ReactNode }) => <p className="mt-2 leading-relaxed text-ink-dim">{children}</p>;
const A = ({ href, children }: { href: string; children: React.ReactNode }) => <a className="underline underline-offset-2 hover:text-ink" href={href} rel="noopener noreferrer">{children}</a>;
const Li = ({ children }: { children: React.ReactNode }) => <li>{children}</li>;
const UL = ({ children }: { children: React.ReactNode }) => <ul className="mt-2 list-disc space-y-1.5 pl-5 text-ink-dim">{children}</ul>;

export default function Privacy() {
  return (
    <>
      <SiteHeader />
      <main className="mx-auto w-full max-w-3xl flex-1 px-6 py-6">
        <h1 className="text-3xl font-semibold tracking-tight">Privacy notice</h1>
        <p className="mt-1 text-sm text-ink-faint">Last updated {SITE.privacyUpdated}. The code that does all of this is <A href={SITE.source}>public</A>, so you can check it.</p>
        <P>{SITE.product} is run by <A href={SITE.operatorUrl}>{SITE.operator}</A>. We collect only what is needed to draw the map and show its health and risks. We do not run advertising or analytics trackers, and we do not sell data.</P>

        <H>If you do not sign in</H>
        <P>You can view the demo and map any public repository without an account. We read that public repository through GitHub&apos;s API and keep the resulting map. Like any web host, our hosting provider logs requests (address, time, page) for security and debugging. No cookies are set. If you confirm which monitoring source belongs to which part of the map, that choice is kept in your browser&apos;s local storage (one entry per repository) and never leaves your browser.</P>

        <H>If you sign in with GitHub</H>
        <UL>
          <Li><span className="text-ink">What we receive from GitHub:</span> your GitHub username, numeric ID and avatar link, and an access token that lets us act on your behalf with the read-only permissions you approved. We never receive your GitHub password.</Li>
          <Li><span className="text-ink">Where it lives:</span> in one encrypted, httpOnly cookie named <code className="font-mono text-ink-dim">twin_session</code> in your browser (AES-256-GCM, lasts up to 30 days). The token is not stored on our servers and cannot be read by page scripts. Signing out deletes the cookie.</Li>
          <Li><span className="text-ink">A second short-lived cookie</span>, <code className="font-mono text-ink-dim">twin_oauth</code>, protects the sign-in handshake and expires after 10 minutes.</Li>
          <Li><span className="text-ink">What we use it for:</span> asking GitHub whether you may read a repository (private repositories are shown only to people GitHub says can read them) and reading it.</Li>
        </UL>

        <H>What we store on our servers</H>
        <P>In a managed Postgres database (Neon), tied to the repository, not to a personal profile:</P>
        <UL>
          <Li><span className="text-ink">The map:</span> component names, file paths and short summaries, saved per commit. Not source code.</Li>
          <Li><span className="text-ink">Security findings (latest scan):</span> file, line number, rule, reason and fix advice. For a leaked secret, only its kind and a masked hint of a few characters, never the value. Visible only to people with write access to the repository.</Li>
          <Li><span className="text-ink">Corrections and mappings</span> that people on the team make, and the settings of read-only share links. Share-link secrets are stored only as a one-way hash.</Li>
          <Li><span className="text-ink">Runtime summaries</span> (error counts and latency per five minutes) if you connect a monitoring tool. They are deleted after 7 days.</Li>
        </UL>
        <P>Your source code is downloaded to a temporary folder to be analysed and deleted straight afterwards. It is never written to the database.</P>

        <H>Who else sees data</H>
        <UL>
          <Li><span className="text-ink">GitHub</span> receives requests for the repository you map, and handles your sign-in.</Li>
          <Li><span className="text-ink">Vercel</span> hosts the site and logs requests. <span className="text-ink">Neon</span> hosts the database.</Li>
          <Li><span className="text-ink">OSV.dev</span> (Google&apos;s open vulnerability database) receives package names and versions during a security scan, and nothing else.</Li>
          <Li><span className="text-ink">An AI provider</span> may receive the map&apos;s structure and short summaries (never raw source files) to write plain-English descriptions, if AI is switched on. Private repositories are never sent to a free-tier or training-enabled model.</Li>
          <Li><span className="text-ink">Sentry or other tools you connect</span> are read with credentials you supply, to compute health.</Li>
        </UL>

        <H>Browser extension</H>
        <P>The optional extension runs only on github.com repository pages. It reads the page address to learn <code className="font-mono text-ink-dim">owner/repo</code>, asks this service for the repository&apos;s status, and shows it. It collects nothing else.</P>

        <H>Your choices</H>
        <UL>
          <Li>Sign out at any time to delete your session cookie. Revoke the GitHub App at <A href="https://github.com/settings/installations">github.com/settings/installations</A> to cut off access completely.</Li>
          <Li>Revoke a share link and it stops working immediately.</Li>
          <Li>To have a repository&apos;s stored data deleted, <A href={SITE.issues}>open an issue</A> naming the repository, or ask through GitHub&apos;s private advisory form if you would rather not do so publicly.</Li>
        </UL>

        <H>Security</H>
        <P>Traffic is encrypted. Sessions are encrypted and httpOnly. Access to private data is checked against your own GitHub permissions on every request. Report a vulnerability through <A href={SITE.securityReport}>the private advisory form</A> or see <a className="underline underline-offset-2 hover:text-ink" href="/.well-known/security.txt">security.txt</a>.</P>

        <H>Changes</H>
        <P>If this notice changes, the date above changes and the change is visible in the <A href={SITE.source}>public history</A>.</P>
      </main>
      <SiteFooter />
    </>
  );
}
