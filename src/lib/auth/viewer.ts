import { isPublicRepo } from "@/lib/github/signals";
import { tokenFor } from "@/lib/github/app";
import { oauthConfig, refreshTokens, repoAccess, type RepoAccess } from "./github";
import { parseCookies, readSession, SESSION_COOKIE, SESSION_TTL_MS, seal, secretOk, setCookie, type Session } from "./session";

const REFRESH_WINDOW = 5 * 60_000;
const secureCookies = () => process.env.NODE_ENV === "production" || (process.env.APP_URL ?? "").startsWith("https:");

export interface Viewer { session: Session; /** Set-Cookie value to attach to the response, when the token was refreshed */ setCookie?: string }

/** The signed-in user for a request, refreshing their GitHub token when it is about to expire. Null when signed out. */
export async function viewerOf(req: Request, o: { env?: NodeJS.ProcessEnv; fetch?: typeof fetch; now?: number } = {}): Promise<Viewer | null> {
  const env = o.env ?? process.env;
  const secret = env.SESSION_SECRET;
  if (!secretOk(secret)) return null;
  const now = o.now ?? Date.now();
  let session = readSession(parseCookies(req.headers.get("cookie"))[SESSION_COOKIE], secret, now);
  if (!session) return null;
  if (session.tokenExp - now > REFRESH_WINDOW) return { session };

  const cfg = oauthConfig(env);
  if (!session.refresh || !cfg) return session.tokenExp > now ? { session } : null;
  try {
    const t = await refreshTokens(cfg, session.refresh, o.fetch ?? fetch, now);
    session = { ...session, token: t.token, refresh: t.refresh ?? session.refresh, tokenExp: t.tokenExp, exp: now + SESSION_TTL_MS };
    return { session, setCookie: setCookie(SESSION_COOKIE, seal(session, secret), { maxAgeSec: SESSION_TTL_MS / 1000, secure: secureCookies() }) };
  } catch { return null; } // refresh token revoked or expired: signed out
}

export type Authz =
  | { ok: true; /** token to read the repo with (installation token if the App is installed, else the user's) */ token?: string; private: boolean; access?: RepoAccess; /** the signed-in user, if any */ login?: string; setCookie?: string }
  | { ok: false; status: 401 | 403 | 429 | 502; message: string };

/**
 * The single rule for who may see a repo:
 *  - a public repo: anyone (read with the shared token for rate limit, if any);
 *  - anything else: only a signed-in user whom GitHub (asked with THEIR token) says can read it.
 * The App's token is used for reading only AFTER that check passes, so it can never reveal a repo to someone GitHub would refuse.
 */
export async function authorizeRepo(req: Request, repo: string, o: { need?: "read" | "push"; deps?: { isPublic?: typeof isPublicRepo; access?: typeof repoAccess; appToken?: typeof tokenFor; viewer?: typeof viewerOf } } = {}): Promise<Authz> {
  const d = { isPublic: isPublicRepo, access: repoAccess, appToken: tokenFor, viewer: viewerOf, ...o.deps };
  const need = o.need ?? "read";
  let pub: boolean;
  try { pub = await d.isPublic(repo); } catch (e) { return { ok: false, status: 429, message: e instanceof Error ? e.message : "Could not reach GitHub." }; }

  const v = await d.viewer(req);
  if (pub && need === "read") return { ok: true, private: false, token: await d.appToken(repo), login: v?.session.login, setCookie: v?.setCookie };
  if (!v) return { ok: false, status: 401, message: pub ? "Sign in with GitHub to do that." : "This repository is private or doesn't exist. Sign in with GitHub and install the app to see private repositories." };

  let access: RepoAccess;
  try { access = await d.access(v.session.token, repo); } catch { return { ok: false, status: 502, message: "Could not check your access with GitHub." }; }
  if (!access.read) return { ok: false, status: 403, message: "GitHub says your account can't see this repository." };
  if (need === "push" && !access.push) return { ok: false, status: 403, message: "You need write access to this repository to change it." };
  return { ok: true, private: access.private, access, login: v.session.login, token: (await d.appToken(repo, { installationOnly: true })) ?? v.session.token, setCookie: v.setCookie };
}

/** Attach a refreshed-session cookie to a response. */
export function withSetCookie(res: Response, cookie?: string): Response {
  if (cookie) res.headers.append("set-cookie", cookie);
  return res;
}
