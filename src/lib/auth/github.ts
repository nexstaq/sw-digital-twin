import { z } from "zod";

/** GITHUB_WEB_URL / GITHUB_API_URL allow GitHub Enterprise Server and test doubles. */
const web = () => (process.env.GITHUB_WEB_URL ?? "https://github.com").replace(/\/$/, "");
const api = () => (process.env.GITHUB_API_URL ?? "https://api.github.com").replace(/\/$/, "");

export interface OAuthConfig { clientId: string; clientSecret: string }
export function oauthConfig(env = process.env): OAuthConfig | null {
  return env.GITHUB_APP_CLIENT_ID && env.GITHUB_APP_CLIENT_SECRET ? { clientId: env.GITHUB_APP_CLIENT_ID, clientSecret: env.GITHUB_APP_CLIENT_SECRET } : null;
}

export const authorizeUrl = (clientId: string, state: string, redirectUri: string) =>
  `${web()}/login/oauth/authorize?${new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, state, allow_signup: "true" })}`;

const Tokens = z.object({
  access_token: z.string().optional(), refresh_token: z.string().optional(),
  expires_in: z.number().optional(), error: z.string().optional(), error_description: z.string().optional(),
});
export interface Tokens { token: string; refresh?: string; tokenExp: number }

async function tokenRequest(cfg: OAuthConfig, params: Record<string, string>, f: typeof fetch, now: number): Promise<Tokens> {
  const res = await f(`${web()}/login/oauth/access_token`, {
    method: "POST", headers: { accept: "application/json", "content-type": "application/x-www-form-urlencoded", "user-agent": "sw-digital-twin" },
    body: new URLSearchParams({ client_id: cfg.clientId, client_secret: cfg.clientSecret, ...params }),
  });
  const t = Tokens.parse(await res.json());
  if (!res.ok || t.error || !t.access_token) throw new Error(t.error_description ?? t.error ?? "GitHub did not return a token.");
  // GitHub Apps with expiring tokens return expires_in (8h); non-expiring return none, so treat as long-lived
  return { token: t.access_token, refresh: t.refresh_token, tokenExp: now + (t.expires_in ?? 365 * 86_400) * 1000 };
}
export const exchangeCode = (cfg: OAuthConfig, code: string, redirectUri: string, f: typeof fetch = fetch, now = Date.now()) =>
  tokenRequest(cfg, { code, redirect_uri: redirectUri }, f, now);
export const refreshTokens = (cfg: OAuthConfig, refresh: string, f: typeof fetch = fetch, now = Date.now()) =>
  tokenRequest(cfg, { grant_type: "refresh_token", refresh_token: refresh }, f, now);

async function ghJson<T>(path: string, token: string, schema: z.ZodType<T>, f: typeof fetch): Promise<T | null> {
  const res = await f(`${api()}${path}`, { headers: { accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "sw-digital-twin", authorization: `Bearer ${token}` }, cache: "no-store" });
  if (res.status === 401 || res.status === 403 || res.status === 404) return null;
  if (!res.ok) throw new Error(`GitHub returned ${res.status}.`);
  return schema.parse(await res.json());
}

const User = z.object({ id: z.number(), login: z.string(), avatar_url: z.string().nullish() });
export const fetchUser = (token: string, f: typeof fetch = fetch) => ghJson("/user", token, User, f);

export interface RepoAccess { read: boolean; push: boolean; private: boolean }
const RepoPerm = z.object({ private: z.boolean(), permissions: z.object({ pull: z.boolean().optional(), push: z.boolean().optional(), admin: z.boolean().optional() }).optional() });

const accessCache = new Map<string, { at: number; v: RepoAccess }>();
const ACCESS_TTL = 2 * 60_000;

/** What THIS user can do to a repo, asked of GitHub with THEIR token. This (not our app token) is what authorises private data. */
export async function repoAccess(token: string, repo: string, f: typeof fetch = fetch, now = Date.now()): Promise<RepoAccess> {
  const k = `${token.slice(-12)}:${repo.toLowerCase()}`;
  const hit = accessCache.get(k);
  if (hit && now - hit.at < ACCESS_TTL) return hit.v;
  const r = await ghJson(`/repos/${repo}`, token, RepoPerm, f);
  const v: RepoAccess = r ? { read: r.permissions?.pull ?? true, push: !!(r.permissions?.push || r.permissions?.admin), private: r.private } : { read: false, push: false, private: true };
  if (accessCache.size > 5000) accessCache.clear();
  accessCache.set(k, { at: now, v });
  return v;
}

const Installs = z.object({ installations: z.array(z.object({ id: z.number(), account: z.object({ login: z.string(), avatar_url: z.string().nullish() }).nullable() })) });
const InstallRepos = z.object({ repositories: z.array(z.object({ full_name: z.string(), private: z.boolean(), description: z.string().nullish(), language: z.string().nullish(), pushed_at: z.string().nullish(), permissions: z.object({ push: z.boolean().optional(), admin: z.boolean().optional() }).optional() })) });

export interface RepoCard { fullName: string; private: boolean; description?: string; language?: string; pushedAt?: string; canPush: boolean; owner: string }

/** Repos the App can see for this user, across their installations. Capped so one huge org cannot stall the page. */
export async function listRepos(token: string, f: typeof fetch = fetch, caps = { installs: 20, repos: 100 }): Promise<RepoCard[]> {
  const inst = await ghJson(`/user/installations?per_page=${caps.installs}`, token, Installs, f);
  const out: RepoCard[] = [];
  await Promise.all((inst?.installations ?? []).map(async (i) => {
    const r = await ghJson(`/user/installations/${i.id}/repositories?per_page=${caps.repos}`, token, InstallRepos, f);
    for (const x of r?.repositories ?? []) out.push({ fullName: x.full_name, private: x.private, description: x.description ?? undefined, language: x.language ?? undefined, pushedAt: x.pushed_at ?? undefined, canPush: !!(x.permissions?.push || x.permissions?.admin), owner: i.account?.login ?? x.full_name.split("/")[0] });
  }));
  return out.sort((a, b) => Date.parse(b.pushedAt ?? "0") - Date.parse(a.pushedAt ?? "0"));
}
