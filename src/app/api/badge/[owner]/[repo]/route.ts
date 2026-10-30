import { parseRepo } from "@/lib/ingest/repo";
import { LIMITS, rateLimit } from "@/lib/security/ratelimit";
import { renderBadge, type BadgeTone } from "@/lib/share/badge";
import { openSharedView, viewVerdict } from "@/lib/share/view";

const svg = (value: string, tone: BadgeTone, cache: string) =>
  new Response(renderBadge("launch", value, tone), { headers: { "content-type": "image/svg+xml; charset=utf-8", "cache-control": cache, "x-content-type-options": "nosniff", "cross-origin-resource-policy": "cross-origin" } });

/**
 * GO / HOLD / NO-GO as an embeddable SVG. Public repos: no token. Private repos: `?t=<share secret>`.
 * "Private or missing" and "bad token" answer identically ("unavailable"), so a badge URL cannot probe for repos.
 */
export async function GET(req: Request, ctx: { params: Promise<{ owner: string; repo: string }> }) {
  if (!rateLimit(req, LIMITS.badge).ok) return svg("busy", "unknown", "public, max-age=30");
  const { owner, repo } = await ctx.params;
  let slug: string;
  try { const r = parseRepo(`${owner}/${repo.replace(/\.svg$/, "")}`); slug = `${r.owner}/${r.name}`.toLowerCase(); } catch { return svg("unavailable", "unknown", "public, max-age=300"); }
  const t = new URL(req.url).searchParams.get("t") ?? undefined;

  const v = await openSharedView(slug, t);
  if (!v.ok) return svg(v.reason === "unmapped" ? "not mapped" : "unavailable", "unknown", "public, max-age=60");
  const verdict = viewVerdict(v);
  // a link-protected badge must not be cached by shared caches, or the token's holder list leaks via the CDN
  return svg(verdict.word, verdict.tone, t ? "private, max-age=60" : "public, max-age=60, s-maxage=60, stale-while-revalidate=300");
}
