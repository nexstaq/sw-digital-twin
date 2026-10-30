# Mission Control for Code: browser extension

Adds a **View Twin** button with a **GO / HOLD / NO-GO** badge to every `github.com/<owner>/<repo>` page. It links to the live map in
the web app. Chrome, Edge and other Chromium browsers (Manifest V3). No account of its own: private repos work through your
existing sign-in to Mission Control.

## What it can and cannot see
- Runs only on `https://github.com/*/*`. It reads **only the URL** to learn `owner/repo`. It does not read the page.
- Talks only to one host: the Mission Control origin it was built for (`host_permissions` in the built manifest). The page's own
  scripts cannot see the request, the response, or any cookie; a background worker makes the call.
- Sends only `owner/repo`. Receives only `{word, tone, why}`. No token ever reaches the page.
- Needs **no** `tabs`, `storage`, `cookies` or `activeTab` permissions.

## Build and install (testing, no store needed)
```bash
npm run ext:build                       # -> extension/dist, talks to https://sw-digital-twin.nexstaq.com
TWIN_ORIGIN=http://localhost:3000 node extension/build.mjs   # against a local dev server
```
Chrome: open `chrome://extensions`, switch on **Developer mode**, **Load unpacked**, choose `extension/dist`.
Open any repo on github.com: the button appears next to Watch / Fork / Star (or as a floating button if GitHub's markup changes).

## Publish
`npm run ext:zip` writes `extension/mission-control-extension.zip` for the Chrome Web Store (one-time $5 developer fee, review
takes days) and the Edge Add-ons store (free). In the store listing, state the single-purpose and privacy points above.

## How it behaves
| State | Button shows | Links to |
|---|---|---|
| Mapped, public or you are signed in | `✓ GO` / `! HOLD` / `✕ NO-GO` / `? NO DATA` | the map |
| Not mapped yet | `? Map it` | the scan page, which builds it |
| Private repo, not signed in | `? Sign in` | sign-in, then back to the map |
| Mission Control unreachable | `? offline` | the map |
Verdicts are reused for 60 s; anything else for 5 s, and a tab that becomes visible again re-checks, so signing in elsewhere
updates the badge without a reload. Every status uses a shape and a word, never colour alone.

## Layout
`manifest.json` · `src/background.ts` (the only network code) · `src/content.ts` (the button, in a Shadow DOM so GitHub's CSS
cannot touch it) · `src/repo.ts` and `src/status.ts` (pure, unit-tested) · `build.mjs` (esbuild) · `icons.mjs` (renders the PNGs).
End-to-end tests load the real extension in Chromium: `e2e/extension.spec.ts`.
