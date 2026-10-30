import type { Metadata } from "next";
import Link from "next/link";
import { SiteFooter, SiteHeader } from "@/components/site/SiteChrome";
import { SITE } from "@/lib/site";

export const metadata: Metadata = {
  title: `About · ${SITE.product}`,
  description: `What ${SITE.product} is, who runs it, what access it asks for, and what it does and does not do.`,
};

const H = ({ children }: { children: React.ReactNode }) => <h2 className="mt-10 text-lg font-semibold">{children}</h2>;
const P = ({ children }: { children: React.ReactNode }) => <p className="mt-2 leading-relaxed text-ink-dim">{children}</p>;
const A = ({ href, children }: { href: string; children: React.ReactNode }) => <a className="underline underline-offset-2 hover:text-ink" href={href} rel="noopener noreferrer">{children}</a>;

export default function About() {
  return (
    <>
      <SiteHeader />
      <main className="mx-auto w-full max-w-3xl flex-1 px-6 py-6">
        <h1 className="text-3xl font-semibold tracking-tight">About {SITE.product}</h1>
        <P>{SITE.product} is a tool for engineering teams. Give it a GitHub repository and it draws a live map of the software: what it is made of, how it is built and deployed, whether it is healthy right now, and where it carries security risk.</P>

        <H>Who runs it</H>
        <P>It is built and operated by <A href={SITE.operatorUrl}>{SITE.operator}</A>, an individual developer, and is open source: <A href={SITE.source}>{SITE.source.replace("https://", "")}</A>. It is not a company product and is not affiliated with, endorsed by or sponsored by GitHub, Inc.</P>
        <P>To reach the operator, <A href={SITE.issues}>open an issue</A>. To report a security problem privately, use <A href={SITE.securityReport}>GitHub&apos;s private advisory form</A>.</P>

        <H>What it does</H>
        <ul className="mt-2 list-disc space-y-1.5 pl-5 text-ink-dim">
          <li><span className="text-ink">The map.</span> Reads a repository&apos;s workflows, containers, package manifests and code structure to show the system from the whole down to a file.</li>
          <li><span className="text-ink">Health.</span> Colours each part by live signals: recent CI runs, deployments and, if connected, error rates.</li>
          <li><span className="text-ink">Security view.</span> Finds vulnerable dependencies, leaked keys and unsafe pipeline or container settings, pinned to the file and line.</li>
          <li><span className="text-ink">Sharing.</span> Read-only share links and a status badge, which the owner can revoke at any time.</li>
          <li><span className="text-ink">Browser extension.</span> An optional extension adds a status button to GitHub repository pages.</li>
        </ul>

        <H>What access it asks for</H>
        <P>Public repositories need no sign-in and no access at all. For private repositories you sign in with GitHub and install the <A href={SITE.appPage}>sw-digital-twin GitHub App</A> on the repositories you choose. The App asks for <span className="text-ink">read-only</span> access to repository contents, GitHub Actions, deployments, checks and metadata. It cannot change your code, open pull requests or write to anything.</P>
        <P>Signing in happens on github.com. This site never sees your GitHub password.</P>

        <H>What it keeps, and what it does not</H>
        <P>Your source code is downloaded to a temporary folder, analysed, and deleted straight afterwards. We keep the resulting map (component names, file paths and short summaries) and security findings (a file, a line number, the rule and the reason), never your source code and never the value of a secret. The <Link className="underline underline-offset-2 hover:text-ink" href="/privacy">privacy notice</Link> lists everything in detail.</P>
        <P>Vulnerability findings are visible only to people with write access to that repository. Share links and the badge never include them.</P>

        <H>Limits you should know about</H>
        <ul className="mt-2 list-disc space-y-1.5 pl-5 text-ink-dim">
          <li>The map is inferred from files, so it can be wrong. You can correct a part and the correction is kept.</li>
          <li>Security checks are automated and best-effort. They can report things that are not real problems and can miss real ones. A clean result means these checks passed, not that the software is proven secure.</li>
          <li>It does not attack your systems. It only reads your repository and public vulnerability data.</li>
        </ul>
      </main>
      <SiteFooter />
    </>
  );
}
