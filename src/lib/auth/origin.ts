/** Public origin of this app, for OAuth redirect URIs. APP_URL wins; otherwise what the request says. */
export function appOrigin(req: Request, env = process.env): string {
  if (env.APP_URL) return env.APP_URL.replace(/\/$/, "");
  const u = new URL(req.url);
  const host = req.headers.get("x-forwarded-host") ?? u.host;
  const proto = req.headers.get("x-forwarded-proto") ?? u.protocol.replace(":", "");
  return `${proto}://${host}`;
}
export const secureCookies = (req: Request, env = process.env) => appOrigin(req, env).startsWith("https:");
