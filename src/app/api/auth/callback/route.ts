import { exchangeCode, fetchUser, oauthConfig } from "@/lib/auth/github";
import { appOrigin, secureCookies } from "@/lib/auth/origin";
import { clearCookie, OAUTH_COOKIE, open, parseCookies, safeEqual, safeReturnTo, seal, secretOk, SESSION_COOKIE, SESSION_TTL_MS, setCookie, type Session } from "@/lib/auth/session";

const back = (req: Request, path: string, cookies: string[]) => {
  const h = new Headers({ location: `${appOrigin(req)}${path}`, "cache-control": "no-store" });
  for (const c of cookies) h.append("set-cookie", c);
  return new Response(null, { status: 302, headers: h });
};

/** GitHub sends the user back here with ?code&state. Verifies state, trades the code for tokens, starts the session. */
export async function GET(req: Request) {
  const cfg = oauthConfig();
  const secret = process.env.SESSION_SECRET;
  const secure = secureCookies(req);
  const dropState = clearCookie(OAUTH_COOKIE, secure).replace("Path=/;", "Path=/api/auth;");
  if (!cfg || !secretOk(secret)) return back(req, "/repos?auth_error=not_configured", [dropState]);

  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const saved = open<{ state: string; returnTo: string; exp: number }>(parseCookies(req.headers.get("cookie"))[OAUTH_COOKIE], secret);
  if (url.searchParams.get("error")) return back(req, "/repos?auth_error=denied", [dropState]);
  if (!code || !state || !saved || saved.exp < Date.now() || !safeEqual(saved.state, state)) return back(req, "/repos?auth_error=bad_state", [dropState]);

  try {
    const t = await exchangeCode(cfg, code, `${appOrigin(req)}/api/auth/callback`);
    const user = await fetchUser(t.token);
    if (!user) return back(req, "/repos?auth_error=no_user", [dropState]);
    const session: Session = { id: user.id, login: user.login, avatar: user.avatar_url ?? undefined, token: t.token, refresh: t.refresh, tokenExp: t.tokenExp, exp: Date.now() + SESSION_TTL_MS };
    return back(req, safeReturnTo(saved.returnTo), [dropState, setCookie(SESSION_COOKIE, seal(session, secret), { maxAgeSec: SESSION_TTL_MS / 1000, secure })]);
  } catch {
    return back(req, "/repos?auth_error=exchange_failed", [dropState]);
  }
}
