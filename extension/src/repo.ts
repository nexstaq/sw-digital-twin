/** First path segments of github.com that are products, not accounts. A repo page is always /<owner>/<repo>[/...]. */
const NOT_AN_OWNER = new Set([
  "about", "account", "apps", "codespaces", "collections", "customer-stories", "dashboard", "enterprise", "events", "explore",
  "features", "issues", "join", "login", "logout", "marketplace", "new", "notifications", "orgs", "organizations", "pricing",
  "pulls", "readme", "search", "security", "sessions", "settings", "site", "sponsors", "stars", "topics", "trending", "users", "watching",
]);

/** "owner/repo" for a github.com repository page, or null for anything else (profile, settings, search, …). */
export function repoFromPath(pathname: string): string | null {
  const [owner, name] = pathname.split("/").filter(Boolean);
  if (!owner || !name) return null;
  if (NOT_AN_OWNER.has(owner.toLowerCase())) return null;
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/.test(owner)) return null;
  if (!/^[\w.-]{1,100}$/.test(name) || name === "." || name === "..") return null;
  return `${owner}/${name.replace(/\.git$/, "")}`;
}
