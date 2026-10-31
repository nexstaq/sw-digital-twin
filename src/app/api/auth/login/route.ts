import { randomBytes } from "node:crypto";
import { authorizeUrl, oauthConfig } from "@/lib/auth/github";
import { appOrigin, secureCookies } from "@/lib/auth/origin";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";
import { OAUTH_COOKIE, safeReturnTo, seal, secretOk, setCookie } from "@/lib/auth/session";

/**
 * Old and bookmarked links land here with GET. They are sent to our own explanation page, never straight to GitHub: a bare URL on
 * this site that instantly redirects to a GitHub login is exactly what a phishing redirector looks like to a crawler. The
 * hand-off to GitHub only happens when a person presses the button on /signin (a POST, which crawlers do not submit).
 */
export async function GET(req: Request) {
  const rl = rateLimit(req, LIMITS.login);
  if (!rl.ok) return tooMany(rl);
  const returnTo = safeReturnTo(new URL(req.url).searchParams.get("returnTo"));
  return new Response(null, { status: 302, headers: { location: `/signin?returnTo=${encodeURIComponent(returnTo)}`, "cache-control": "no-store" } });
}

/** Starts "Sign in with GitHub" (the GitHub App's user authorization). Reached by the button on /signin. */
export async function POST(req: Request) {
  const rl = rateLimit(req, LIMITS.login);
  if (!rl.ok) return tooMany(rl);
  const cfg = oauthConfig();
  const secret = process.env.SESSION_SECRET;
  if (!cfg || !secretOk(secret)) return Response.json({ error: "Sign-in is not configured (GITHUB_APP_CLIENT_ID, GITHUB_APP_CLIENT_SECRET, SESSION_SECRET)." }, { status: 503 });

  const form = await req.formData().catch(() => null);
  const state = randomBytes(16).toString("hex");
  const returnTo = safeReturnTo(String(form?.get("returnTo") ?? ""));
  const cookie = setCookie(OAUTH_COOKIE, seal({ state, returnTo, exp: Date.now() + 10 * 60_000 }, secret), { maxAgeSec: 600, secure: secureCookies(req), path: "/api/auth" });
  // 303: the browser follows a POST redirect with a GET, which is what GitHub's authorize endpoint expects
  return new Response(null, { status: 303, headers: { location: authorizeUrl(cfg.clientId, state, `${appOrigin(req)}/api/auth/callback`), "set-cookie": cookie, "cache-control": "no-store" } });
}
