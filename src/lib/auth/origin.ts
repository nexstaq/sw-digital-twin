const trim = (s: string) => s.trim().replace(/\/$/, "");

/** What the request says its public origin is (the platform sets the forwarded headers). */
function requestOrigin(req: Request): string {
  const u = new URL(req.url);
  const host = req.headers.get("x-forwarded-host") ?? u.host;
  const proto = req.headers.get("x-forwarded-proto") ?? u.protocol.replace(":", "");
  return `${proto}://${host}`;
}

/**
 * Public origin of this app, for OAuth redirect URIs and the links we hand out.
 *  - With APP_URL set, the app answers on that origin, and on any origin listed in APP_ALIAS_URLS (comma-separated). The request's
 *    own origin is used only when it matches one of those EXACTLY, so a spoofed host header can never steer a redirect elsewhere.
 *    (GitHub also refuses any callback that is not registered on the App, so an alias works only once it is registered there.)
 *  - Without APP_URL (local dev, previews) it is whatever the request says.
 */
export function appOrigin(req: Request, env = process.env): string {
  const primary = env.APP_URL ? trim(env.APP_URL) : "";
  const own = requestOrigin(req);
  if (!primary) return own;
  const allowed = [primary, ...(env.APP_ALIAS_URLS ?? "").split(",").map(trim).filter(Boolean)];
  return allowed.includes(own) ? own : primary;
}
export const secureCookies = (req: Request, env = process.env) => appOrigin(req, env).startsWith("https:");
