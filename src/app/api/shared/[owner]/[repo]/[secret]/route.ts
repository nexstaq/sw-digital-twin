import { parseRepo } from "@/lib/ingest/repo";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";
import { openSharedView } from "@/lib/share/view";

const NO_STORE = { "cache-control": "private, no-store" };

/** The read-only view behind a share link: last saved map plus live health. Revoking the link stops this at once. */
export async function GET(req: Request, ctx: { params: Promise<{ owner: string; repo: string; secret: string }> }) {
  const rl = rateLimit(req, LIMITS.shared);
  if (!rl.ok) return tooMany(rl);
  const { owner, repo, secret } = await ctx.params;
  let slug: string;
  try { const r = parseRepo(`${owner}/${repo}`); slug = `${r.owner}/${r.name}`.toLowerCase(); } catch { return Response.json({ error: "This link doesn't work." }, { status: 404, headers: NO_STORE }); }
  const v = await openSharedView(slug, secret, { requireSecret: true });
  if (!v.ok) {
    return v.reason === "unmapped"
      ? Response.json({ error: "This link is valid, but the repository hasn't been mapped yet." }, { status: 404, headers: NO_STORE })
      : Response.json({ error: "This link doesn't work. It may have been revoked." }, { status: 404, headers: NO_STORE });
  }
  return Response.json({ repo: v.repo, graph: v.graph, signals: v.signals, warning: v.warning }, { headers: NO_STORE });
}
