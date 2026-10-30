# Sign-in, private repos, access control (P4b)

## Decision: GitHub App user authorization instead of Clerk
The plan said "Clerk via the Marketplace". v1 is GitHub-only, and the thing that actually authorises access to a private repo is **the user's own GitHub token**, so the GitHub App's "Sign in with GitHub" (user-to-server OAuth) gives login **and** repo access from one registration, with no second vendor and no user table. Auth sits behind small functions (`viewerOf`, `authorizeRepo`), so Clerk (or another provider) can be added later if you want email/SSO logins; nothing else depends on how the user is identified.

## The rule (one function: `authorizeRepo`, src/lib/auth/viewer.ts)
- **Public repo**: anyone may read it.
- **Anything else**: only a signed-in user whom **GitHub, asked with THEIR token**, says can read it (`GET /repos/{r}` → `permissions.pull`). Only after that check do we read data with the App's installation token (or, if the App is not installed on that repo, the user's own token). The shared `GITHUB_TOKEN` is never used for private repos.
- **Writes** (shared mappings) need `push` access.
- Used by: `/api/scan`, `/api/health/stream`, `/api/snapshots`, `/api/mappings`. A GitHub outage while checking is a 502, never an accidental "allow".

## Sessions
One httpOnly, SameSite=Lax (Secure over https) cookie, **sealed with AES-256-GCM** from `SESSION_SECRET`. It holds the session including the GitHub token, so the token never reaches page JavaScript and there is no session table. GitHub tokens expire after 8h; `/api/auth/me` (called on page load) and any authorised route refresh them with the refresh token and re-issue the cookie; a revoked refresh token signs the user out. Sign-out is `POST /api/auth/logout`. OAuth uses a random `state` (sealed in a short-lived cookie, constant-time compared); post-login redirects accept only same-site relative paths.

## Private repos
- Scan: clone with the installation token passed **only through git's environment config** (`GIT_CONFIG_COUNT/KEY/VALUE`), scoped to that host: never in argv, the URL or `.git/config`. Verified with real git against a local server (header sent to that origin, not to another).
- **AI privacy**: private repos never use the free Gemini dev key (`allowDevKey: false`); only the AI Gateway can describe or answer questions about them, otherwise rule-based text is used. `/api/ask` treats any repo it cannot prove public as private.
- Stored maps (`/api/snapshots`) are readable only by users GitHub says can read the repo.

## Shared mappings
Confirming a signal -> node match saves it on the server when you have push access (everyone who can see the repo then sees it); otherwise it stays in your browser. Replaces the browser-only stopgap from P6.

## Set up (you do this once)
1. https://github.com/settings/apps/new (or an organisation's settings). Use the manifest in `docs/HEALTH.md`, **plus**:
   - **Callback URL**: `https://YOUR-HOST/api/auth/callback` (and `http://localhost:3000/api/auth/callback` for dev).
   - **Expire user authorization tokens**: on (default).
   - **Request user authorization (OAuth) during installation**: on.
   - Permissions (read-only): Metadata, Contents, Actions, Deployments, Checks; "Account: Email" is not needed.
2. Generate a **client secret** and a **private key** (.pem). Note the App ID and Client ID.
3. Note: newer GitHub UI keeps **Client secrets** and **Private keys** under the **Credentials** tab, and calls the callback field "Redirect URI". The App ID must be the plain number. Set env (Vercel project settings, or `.env.local`): `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET`, `GITHUB_APP_SLUG`, `GITHUB_WEBHOOK_SECRET`, `SESSION_SECRET`, and `APP_URL`.
4. Open `/repos`, **Sign in with GitHub**, then **Add repositories** to install the App on the ones you want.

## Verified vs not
Verified (unit tests: 26 for auth, plus a real-git check): sealing/tamper/expiry, OAuth exchange/refresh, access mapping, the full allow/deny matrix of `authorizeRepo`, clone-auth env. In a browser against a **mock GitHub**: sign-in, httpOnly cookie, repo picker with a private repo, private health stream allowed only while signed in, anonymous refused, shared mappings (read-all / write-push), sign-out.
**Verified against real GitHub (2026-10-29)**, with the App registered under a personal account: real sign-in and consent, the repo picker, an installation token minted from the App's private key, a real private-repo clone with that token (142 nodes in 3.3s), live health from its real workflow runs, and refusal of anonymous access to it.
**Still unverified**: token refresh after the 8-hour expiry, App installation on an organisation, GitHub Enterprise Server, and deployed (https) cookies.

## Not built
Per-team connector credentials (Sentry/Vercel tokens are still the operator's, gated by `CONNECTOR_REPOS`), org-level roles, rate limiting per user, Clerk adapter, `installation` webhooks (repo added/removed live), deploying to Vercel (needs the Vercel CLI: `npm i -g vercel`).
