import { createSign } from "node:crypto";
import { z } from "zod";

/** GitHub App credentials come from env. Newlines in the PEM may be escaped as \n. */
export function appConfig(env = process.env): { appId: string; privateKey: string } | null {
  const appId = env.GITHUB_APP_ID;
  const key = env.GITHUB_APP_PRIVATE_KEY;
  return appId && key ? { appId, privateKey: key.replace(/\\n/g, "\n") } : null;
}

const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");

/** RS256 JWT identifying the App itself (valid <= 10 minutes). Used only to ask for installation tokens. */
export function appJwt(appId: string, privateKey: string, nowSec = Math.floor(Date.now() / 1000)): string {
  const head = b64u(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const body = b64u(JSON.stringify({ iat: nowSec - 30, exp: nowSec + 9 * 60, iss: appId }));
  const sig = createSign("RSA-SHA256").update(`${head}.${body}`).sign(privateKey);
  return `${head}.${body}.${b64u(sig)}`;
}

const apiBase = () => (process.env.GITHUB_API_URL ?? "https://api.github.com").replace(/\/$/, "");
const Token = z.object({ token: z.string(), expires_at: z.string() });
const cache = new Map<string, { token: string; exp: number }>();

/**
 * Token to read `owner/name` with. Order: App installation token (works for private repos the App is installed on),
 * then GITHUB_TOKEN, then undefined (public repos, 60 requests/hour). Never throws: no access just means no token.
 */
export async function tokenFor(repo: string, o: { fetch?: typeof fetch; env?: NodeJS.ProcessEnv; /** private repos: never fall back to the shared GITHUB_TOKEN */ installationOnly?: boolean } = {}): Promise<string | undefined> {
  const env = o.env ?? process.env;
  const cfg = appConfig(env);
  if (cfg) {
    const hit = cache.get(repo);
    if (hit && hit.exp - Date.now() > 5 * 60_000) return hit.token;
    try {
      const f = o.fetch ?? fetch;
      const headers = { accept: "application/vnd.github+json", "user-agent": "sw-digital-twin", authorization: `Bearer ${appJwt(cfg.appId, cfg.privateKey)}` };
      const inst = await f(`${apiBase()}/repos/${repo}/installation`, { headers });
      if (inst.ok) {
        const { id } = z.object({ id: z.number() }).parse(await inst.json());
        const tok = await f(`${apiBase()}/app/installations/${id}/access_tokens`, { method: "POST", headers });
        if (tok.ok) {
          const t = Token.parse(await tok.json());
          cache.set(repo, { token: t.token, exp: Date.parse(t.expires_at) });
          return t.token;
        }
      }
    } catch { /* fall through to the shared token */ }
  }
  return o.installationOnly ? undefined : env.GITHUB_TOKEN || undefined;
}
