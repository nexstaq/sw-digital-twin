"use client";

import { useSyncExternalStore } from "react";
import { LogIn, ShieldCheck } from "lucide-react";
import { SITE } from "@/lib/site";

const subscribe = () => () => {};
const returnToFromUrl = () => new URLSearchParams(window.location.search).get("returnTo") ?? "/repos";

/**
 * The page between "Sign in" and GitHub. It says what is about to happen and what is NOT, and only a button press (a form POST)
 * continues to GitHub, so nothing on this site redirects to a login page by itself.
 */
export function SignInCard() {
  const returnTo = useSyncExternalStore(subscribe, returnToFromUrl, () => "/repos");
  return (
    <div className="mx-auto w-full max-w-md rounded-2xl border border-line bg-surface p-7">
      <div className="flex items-center gap-2.5 text-accent"><ShieldCheck size={20} aria-hidden /><h1 className="text-xl font-semibold text-ink">Sign in with GitHub</h1></div>
      <p className="mt-3 text-sm leading-relaxed text-ink-dim">
        {SITE.product} uses your GitHub account only to find out which repositories you can see. Pressing the button takes you to <span className="font-mono text-ink">github.com</span>, where <em>GitHub</em> asks you to approve access.
      </p>
      <ul className="mt-4 space-y-1.5 text-sm text-ink-dim">
        <li>• Access is <span className="text-ink">read-only</span>: repository contents, workflows, deployments and checks.</li>
        <li>• You enter your GitHub password only on github.com. This site never sees it.</li>
        <li>• It cannot change your code. You can revoke access any time in your GitHub settings.</li>
      </ul>
      <form method="post" action="/api/auth/login" className="mt-6">
        <input type="hidden" name="returnTo" value={returnTo} />
        <button className="flex w-full items-center justify-center gap-2 rounded-xl bg-accent px-5 py-3 text-sm font-medium text-void"><LogIn size={16} aria-hidden /> Continue to GitHub</button>
      </form>
      <p className="mt-4 text-xs leading-relaxed text-ink-faint">
        Public repositories and the demo need no sign-in at all. Built and run by <a className="underline underline-offset-2 hover:text-ink-dim" href={SITE.operatorUrl} rel="noopener noreferrer">{SITE.operator}</a>; the <a className="underline underline-offset-2 hover:text-ink-dim" href={SITE.source} rel="noopener noreferrer">source is public</a>. <a className="underline underline-offset-2 hover:text-ink-dim" href="/privacy">Privacy notice</a>.
      </p>
    </div>
  );
}
