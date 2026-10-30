import { randomBytes } from "node:crypto";
import { authorizeUrl, oauthConfig } from "@/lib/auth/github";
import { appOrigin, secureCookies } from "@/lib/auth/origin";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";
import { OAUTH_COOKIE, safeReturnTo, seal, secretOk, setCookie } from "@/lib/auth/session";

/** Starts "Sign in with GitHub" (the GitHub App's user authorization). */
export async function GET(req: Request) {
  const rl = rateLimit(req, LIMITS.login);
  if (!rl.ok) return tooMany(rl);
  const cfg = oauthConfig();
  const secret = process.env.SESSION_SECRET;
  if (!cfg || !secretOk(secret)) return Response.json({ error: "Sign-in is not configured (GITHUB_APP_CLIENT_ID, GITHUB_APP_CLIENT_SECRET, SESSION_SECRET)." }, { status: 503 });

  const state = randomBytes(16).toString("hex");
  const returnTo = safeReturnTo(new URL(req.url).searchParams.get("returnTo"));
  const cookie = setCookie(OAUTH_COOKIE, seal({ state, returnTo, exp: Date.now() + 10 * 60_000 }, secret), { maxAgeSec: 600, secure: secureCookies(req), path: "/api/auth" });
  return new Response(null, { status: 302, headers: { location: authorizeUrl(cfg.clientId, state, `${appOrigin(req)}/api/auth/callback`), "set-cookie": cookie, "cache-control": "no-store" } });
}
