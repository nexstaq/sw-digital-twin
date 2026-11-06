import { appOrigin } from "@/lib/auth/origin";
import { parseRepo } from "@/lib/ingest/repo";
import { LIMITS, rateLimit } from "@/lib/security/ratelimit";
import { renderEmbed, renderEmbedUnavailable } from "@/lib/share/embed";
import { openSharedView, viewVerdict } from "@/lib/share/view";
import { applyHealth } from "@/lib/health/engine";

const html = (body: string, cache: string, status = 200) =>
  new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": cache, "x-content-type-options": "nosniff", "referrer-policy": "no-referrer" } });

/**
 * A read-only status card for an <iframe>. Public repos need no token; a private repo needs `?t=<share secret>`. "Private", "missing"
 * and "wrong token" all answer the same, so an embed URL cannot be used to probe for repositories. Served with no script and a
 * CSP that lets any site frame it (see next.config.ts); the rest of the app can never be framed.
 */
export async function GET(req: Request, ctx: { params: Promise<{ owner: string; repo: string }> }) {
  if (!rateLimit(req, LIMITS.badge).ok) return html(renderEmbedUnavailable("Busy, try again shortly"), "public, max-age=30", 429);
  const { owner, repo } = await ctx.params;
  let slug: string;
  try { const r = parseRepo(`${owner}/${repo}`); slug = `${r.owner}/${r.name}`.toLowerCase(); } catch { return html(renderEmbedUnavailable("Unavailable"), "public, max-age=300"); }
  const t = new URL(req.url).searchParams.get("t") ?? undefined;

  const v = await openSharedView(slug, t);
  if (!v.ok) return html(renderEmbedUnavailable(v.reason === "unmapped" ? "Not mapped yet" : "Unavailable"), "public, max-age=60");
  const graph = v.signals ? applyHealth(v.graph, v.signals, v.signals.fetchedAt) : v.graph;
  const origin = appOrigin(req);
  // a link that carries a secret must not sit in a shared cache; the "open" link sends the holder to the same read-only page
  const openUrl = t ? `${origin}/s/${slug}/${encodeURIComponent(t)}` : `${origin}/scan?repo=${encodeURIComponent(slug)}`;
  return html(renderEmbed({ repo: slug, verdict: viewVerdict(v), graph, openUrl }), t ? "private, max-age=60" : "public, max-age=60, s-maxage=60, stale-while-revalidate=300");
}
