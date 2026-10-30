import { oauthConfig } from "@/lib/auth/github";
import { secretOk } from "@/lib/auth/session";
import { viewerOf, withSetCookie } from "@/lib/auth/viewer";

/** Who is signed in. Never returns the token. Also where an expiring GitHub token gets refreshed. */
export async function GET(req: Request) {
  // Reading the request marks this route dynamic. Without it the build prerenders the answer for whatever env existed at
  // build time ("not configured") and serves it forever.
  const hasCookie = req.headers.has("cookie");
  const configured = !!oauthConfig() && secretOk(process.env.SESSION_SECRET);
  const v = configured && hasCookie ? await viewerOf(req) : null;
  const slug = process.env.GITHUB_APP_SLUG;
  const web = (process.env.GITHUB_WEB_URL ?? "https://github.com").replace(/\/$/, "");
  const res = Response.json({
    configured,
    user: v ? { login: v.session.login, avatar: v.session.avatar } : null,
    installUrl: slug ? `${web}/apps/${slug}/installations/new` : null,
  }, { headers: { "cache-control": "no-store" } });
  return withSetCookie(res, v?.setCookie);
}
