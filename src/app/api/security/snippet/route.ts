import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { parseRepo } from "@/lib/ingest/repo";
import { persist } from "@/lib/persist";
import { redactLine } from "@/lib/security/analyzers/secrets";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";

const NO_STORE = { "cache-control": "private, no-store" };
const CONTEXT = 4; // lines either side
const MAX_BYTES = 1_000_000;
const apiBase = () => (process.env.GITHUB_API_URL ?? "https://api.github.com").replace(/\/$/, "");

/**
 * The few lines around a finding, fetched from GitHub at view time with the caller's own access: we never store source code.
 * It only serves files that a stored finding points at (not a general file browser), redacts anything that looks like a secret,
 * and for a private key shows the header line only, because the lines after it ARE the key.
 */
export async function GET(req: Request) {
  const rl = rateLimit(req, LIMITS.snippet);
  if (!rl.ok) return tooMany(rl);
  const url = new URL(req.url);
  let repo: string;
  try { const r = parseRepo(url.searchParams.get("repo") ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 400 });
  }
  const path = url.searchParams.get("path") ?? "";
  const line = Number(url.searchParams.get("line"));
  if (!/^[\w@.+\-/ ]{1,300}$/.test(path) || path.split("/").some((s) => s === ".." || s === ".") || path.startsWith("/") || !Number.isInteger(line) || line < 1 || line > 1_000_000) {
    return Response.json({ error: "Bad request." }, { status: 400 });
  }
  const a = await authorizeRepo(req, repo, { need: "push" });
  if (!a.ok) return Response.json({ error: a.message }, { status: a.status, headers: NO_STORE });

  const set = await persist().getFindings(repo);
  const hits = set?.findings.filter((f) => f.path === path) ?? [];
  if (!set || hits.length === 0) return Response.json({ error: "No finding points at that file." }, { status: 404, headers: NO_STORE });
  const isKey = hits.some((f) => f.detail.secretKind === "Private key" && (f.line === line || f.detail.lines?.includes(line)));

  const res = await fetch(`${apiBase()}/repos/${repo}/contents/${path.split("/").map(encodeURIComponent).join("/")}?ref=${set.sha}`, {
    headers: { accept: "application/vnd.github.raw+json", "user-agent": "sw-digital-twin", "x-github-api-version": "2022-11-28", ...(a.token ? { authorization: `Bearer ${a.token}` } : {}) }, cache: "no-store",
  });
  if (!res.ok) return Response.json({ error: res.status === 404 ? "That file is gone at the scanned commit." : "Could not read the file from GitHub." }, { status: res.status === 404 ? 404 : 502, headers: NO_STORE });
  const text = (await res.text()).slice(0, MAX_BYTES);
  const all = text.split("\n");
  if (line > all.length) return Response.json({ error: "That line is past the end of the file." }, { status: 404, headers: NO_STORE });

  const from = isKey ? line : Math.max(1, line - CONTEXT);
  const to = isKey ? line : Math.min(all.length, line + CONTEXT);
  const lines = all.slice(from - 1, to).map((t, i) => ({ n: from + i, text: redactLine(t.slice(0, 240)) }));
  return withSetCookie(Response.json({ sha: set.sha, path, highlight: line, lines, redacted: isKey ? "Only the first line of a private key is shown." : undefined }, { headers: NO_STORE }), a.setCookie);
}
