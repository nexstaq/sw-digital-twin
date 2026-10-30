import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { applyOverrides } from "@/lib/graph/overrides";
import { parseRepo } from "@/lib/ingest/repo";
import { persist } from "@/lib/persist";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";
import { renderReportHtml, toSarif } from "@/lib/security/report";

const NO_STORE = { "cache-control": "private, no-store" };

/**
 * The latest security scan as a report: `html` (print-ready, "Save as PDF" from the browser), `sarif` (GitHub code scanning and most
 * tools) or `json`. Push access only, like every other security endpoint. The HTML carries its own locked-down CSP: it needs no
 * scripts at all, so none are allowed.
 */
export async function GET(req: Request) {
  const rl = rateLimit(req, LIMITS.write);
  if (!rl.ok) return tooMany(rl);
  const url = new URL(req.url);
  let repo: string;
  try { const r = parseRepo(url.searchParams.get("repo") ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 400 });
  }
  const format = url.searchParams.get("format") ?? "html";
  if (!["html", "sarif", "json"].includes(format)) return Response.json({ error: "format must be html, sarif or json." }, { status: 400 });
  const a = await authorizeRepo(req, repo, { need: "push" });
  if (!a.ok) return Response.json({ error: a.message }, { status: a.status, headers: NO_STORE });

  const store = persist();
  const set = await store.getFindings(repo);
  if (!set) return Response.json({ error: "No security scan yet. Run one first." }, { status: 404, headers: NO_STORE });

  const download = url.searchParams.get("download") === "1";
  const base = `security-${repo.replace("/", "-")}-${set.sha.slice(0, 7)}`;
  const disposition = (ext: string): Record<string, string> => (download ? { "content-disposition": `attachment; filename="${base}.${ext}"` } : {});

  let res: Response;
  if (format === "sarif") {
    res = new Response(JSON.stringify(toSarif(set), null, 1), { headers: { "content-type": "application/sarif+json; charset=utf-8", ...NO_STORE, ...disposition("sarif") } });
  } else if (format === "json") {
    res = new Response(JSON.stringify(set, null, 1), { headers: { "content-type": "application/json; charset=utf-8", ...NO_STORE, ...disposition("json") } });
  } else {
    const snap = await store.getSnapshot(repo, (await store.listSnapshots(repo)).at(-1)?.sha ?? "");
    const graph = snap ? applyOverrides(snap.graph, await store.getOverrides(repo)) : undefined;
    res = new Response(renderReportHtml({ set, graph }), {
      headers: { "content-type": "text/html; charset=utf-8", ...NO_STORE, ...disposition("html"), "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", "x-robots-tag": "noindex" },
    });
  }
  return withSetCookie(res, a.setCookie);
}
