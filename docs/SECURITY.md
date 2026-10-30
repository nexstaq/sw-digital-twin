# Security notes

## Browser hardening (`src/lib/security/headers.ts`, wired in `next.config.ts`)
Every response carries CSP, HSTS (production only), `nosniff`, `X-Frame-Options: DENY`, a strict `Referrer-Policy`, a
`Permissions-Policy` that turns off camera/mic/location/payment, and COOP/CORP `same-origin`. `X-Powered-By` is removed.

**Known trade-off:** the CSP is static, so `script-src` includes `'unsafe-inline'` (Next's bootstrap scripts are inline). A
nonce-based CSP would remove it but forces every page to render per request, undoing prerendering (Next CSP guide). What
the policy still blocks: `eval` in production, plugins, foreign script/connect/frame origins, `<base>` and form hijacking,
and being framed. Revisit if the landing page becomes dynamic anyway.

**Embeds (P7):** badge and embed routes must override `frame-ancestors` and `Cross-Origin-Resource-Policy` for themselves
only. Everything else stays locked.

Verified on a production build in Chromium: `/`, `/repos`, `/demo`, `/demo/incident`, `/design`, `/scan` render with zero
CSP violations.

## Rate limits (`src/lib/security/ratelimit.ts`)
Per client address, per route, fixed window: login 20/min, scan 6/min, ask 20/min, health stream 20/min, OTLP 120/min.
In-memory, so each serverless instance counts separately: a brake on one noisy client, not a global quota. Add a Vercel
Firewall rate-limit rule (dashboard) for a global one, and BotID on scan/ask.

## Sign-in
See `docs/AUTH.md`: sealed single-use `state`, httpOnly SameSite=Lax Secure cookies, same-site-only `returnTo`, the token
never reaches page JavaScript.

## "Dangerous site" warnings
Chrome Safe Browsing can flag a brand-new domain that redirects to a login. Code cannot fix that. Check
`transparencyreport.google.com/safe-browsing/search`, verify the domain in Google Search Console (Security issues →
Request review), and report a false positive at `safebrowsing.google.com/safebrowsing/report_error`.

## Share links, badges and overrides (P7)
- **Who can do what.** Read the map: anyone for public repos; signed-in readers for private ones (`authorizeRepo`). Create/revoke share
  links and edit node overrides: push access only, checked with the user's own GitHub token.
- **Share links** are bearer secrets: 192 random bits, shown once, stored only as a SHA-256 hash, compared in constant time over
  all of a repo's links, revocable (takes effect on the next request, including for pages already open). Max 20 live per repo.
  A link opens the *last saved map* plus live health, read-only, with no sign-in. Pages carry `noindex` and `no-referrer`.
- **No probing.** A wrong, revoked or malformed secret, a missing repo and a private repo without a token all answer the same,
  for both `/api/shared/...` and `/api/badge/...`.
- **Badge** `/api/badge/<owner>/<repo>[?t=<secret>]` is the one cross-origin-loadable route (`Cross-Origin-Resource-Policy:
  cross-origin`); token-bearing badges are `private` cached so a CDN cannot hand them to someone without the token.
- **Overrides** (rename, re-describe, hide) are keyed by node id, applied after every scan, and stored per repo. Hidden nodes stay
  listed in a "hidden" menu so they can be restored.
- **Not yet.** Share views show GitHub-derived health only (no Sentry/OTLP runtime layer), and there is no iframe embed.

## BotID (P7)
`/api/scan` (clones a repo) and `/api/ask` (spends model tokens) call `denyBots()` (`src/lib/security/bot.ts`), which uses Vercel
BotID. The browser side is `src/instrumentation-client.ts` (`initBotId`) plus `withBotId` in `next.config.ts`. BotID attaches its
token to `fetch`/XHR only, so the scan page streams with `fetch` (`src/lib/sse.ts`), not `EventSource`.
- Only active on Vercel (`process.env.VERCEL`); elsewhere it is off, so dev, self-hosting and CI are unaffected.
- Fails open if BotID itself errors (logged), because the per-client rate limits still apply.
- Deliberately NOT protected: the badge (GitHub's image proxy must reach it), pages, and sign-in.
- Basic mode is free. "Deep Analysis" is an optional dashboard toggle (Project → Firewall → Configure).
- `RATE_LIMIT_SCALE` multiplies every rate limit (default 1; the e2e suite uses 5).

## Tests
- `npx vitest run`: unit tests. Set `TEST_DATABASE_URL` (a Neon connection string) to also run the Postgres adapter tests.
- `npm run e2e`: Playwright against a production build (built into `.next-e2e`, so it never collides with `next dev`) and a mock
  GitHub (`e2e/mock-github.mjs`, fixture repo in `e2e/fixture/`). Hermetic: no network, no real credentials, real env blanked.
  Covers paste URL -> map -> drill-down -> failing step, private-repo access, sign-in/out, share + revoke, overrides, CSP on
  every page, security headers, anonymous write refusal and rate limiting. CI: `.github/workflows/ci.yml`.

## Browser extension (P7)
See `extension/README.md`. Security shape: runs only on `github.com/*/*`; reads only the URL; the one network call is made by a
background worker to the single host in `host_permissions`; the page world never sees the request, a cookie or a token; the
button is built with `textContent` inside a Shadow DOM. The server side is `/api/verdict`: same `authorizeRepo` rule as every
other route (public: open, private: the caller's own session), `private, no-store`, deliberately **no CORS headers**, rate
limited. The worker's `fetch(..., { credentials: "include" })` carries the SameSite=Lax session cookie (verified in Chromium).
