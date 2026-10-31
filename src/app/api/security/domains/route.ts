import { z } from "zod";
import { authorizeRepo, withSetCookie } from "@/lib/auth/viewer";
import { parseRepo } from "@/lib/ingest/repo";
import { persist } from "@/lib/persist";
import { byPriority } from "@/lib/security/map";
import { instructions, newVerifyToken, parseDomain } from "@/lib/security/passive/domain";
import { runPassiveChecks, verifyOwnership } from "@/lib/security/passive/run";
import { getTransport } from "@/lib/security/passive/transport";
import { LIMITS, rateLimit, tooMany } from "@/lib/security/ratelimit";
import { refreshTrend } from "@/lib/security/trend";
import type { DomainEntry } from "@/lib/security/types";

export const maxDuration = 60;
const NO_STORE = { "cache-control": "private, no-store" };
const MAX_DOMAINS = 5;
const err = (error: string, status: number, extra: object = {}) => Response.json({ error, ...extra }, { status, headers: NO_STORE });
/** a domain can be checked once per this long; the e2e suite shortens it */
const cooldownMs = () => { const v = Number(process.env.PASSIVE_CHECK_COOLDOWN_MS); return Number.isFinite(v) && v >= 0 ? v : 5 * 60_000; };

const Body = z.object({ repo: z.string().max(200), action: z.enum(["add", "verify", "check"]), domain: z.string().max(300) });
const view = (d: DomainEntry) => ({ ...d, instructions: instructions(d.domain, d.token) });

async function gate(req: Request, repoRaw: string | null) {
  let repo: string;
  try { const r = parseRepo(repoRaw ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) { return { fail: err((e as Error).message, 400) }; }
  // testing a live site is for maintainers: push access, checked with the caller's own GitHub token
  const a = await authorizeRepo(req, repo, { need: "push" });
  if (!a.ok) return { fail: err(a.message, a.status) };
  return { repo, a };
}

export async function GET(req: Request) {
  const rl = rateLimit(req, LIMITS.domains);
  if (!rl.ok) return tooMany(rl);
  const g = await gate(req, new URL(req.url).searchParams.get("repo"));
  if (g.fail) return g.fail;
  return withSetCookie(Response.json({ domains: (await persist().getDomains(g.repo)).map(view) }, { headers: NO_STORE }), g.a.setCookie);
}

/**
 * add: register a domain and get its proof token. verify: look for the token in DNS or at /.well-known/. check: re-prove ownership,
 * THEN run the passive checks. Nothing is ever sent to a domain until it has proved ownership, and ownership is re-proved every time.
 */
export async function POST(req: Request) {
  const rl = rateLimit(req, LIMITS.domains);
  if (!rl.ok) return tooMany(rl);
  const body = Body.safeParse(await req.json().catch(() => null));
  if (!body.success) return err("Bad request.", 400);
  const g = await gate(req, body.data.repo);
  if (g.fail) return g.fail;
  const parsed = parseDomain(body.data.domain);
  if (!parsed.ok) return err(parsed.reason, 400);
  const domain = parsed.domain;
  const store = persist();
  const list = await store.getDomains(g.repo);
  const entry = list.find((d) => d.domain === domain);
  const done = (res: Response) => withSetCookie(res, g.a.setCookie);

  if (body.data.action === "add") {
    if (entry) return done(Response.json({ domain: view(entry) }, { headers: NO_STORE }));
    if (list.length >= MAX_DOMAINS) return err(`At most ${MAX_DOMAINS} domains per repository. Remove one first.`, 409);
    const fresh: DomainEntry = { domain, token: newVerifyToken(), createdAt: Date.now() };
    await store.putDomains(g.repo, [...list, fresh]);
    return done(Response.json({ domain: view(fresh) }, { status: 201, headers: NO_STORE }));
  }
  if (!entry) return err("Add that domain first.", 404);
  const transport = getTransport();

  if (body.data.action === "verify") {
    const v = await verifyOwnership(domain, entry.token, transport);
    if (!v.ok) return done(Response.json({ verified: false, reasons: v.reasons, domain: view(entry) }, { headers: NO_STORE }));
    const next = { ...entry, verifiedAt: Date.now(), verifiedVia: v.via };
    await store.putDomains(g.repo, list.map((d) => (d.domain === domain ? next : d)));
    return done(Response.json({ verified: true, via: v.via, domain: view(next) }, { headers: NO_STORE }));
  }

  // check
  const lim = rateLimit(req, LIMITS.passive);
  if (!lim.ok) return tooMany(lim);
  const wait = entry.lastCheckAt ? entry.lastCheckAt + cooldownMs() - Date.now() : 0;
  if (wait > 0) return err(`${domain} was checked a moment ago. Try again in ${Math.ceil(wait / 1000)} seconds.`, 429, { retryAfterSec: Math.ceil(wait / 1000) });
  const proof = await verifyOwnership(domain, entry.token, transport); // every run, not just the first
  if (!proof.ok) {
    await store.putDomains(g.repo, list.map((d) => (d.domain === domain ? { ...d, verifiedAt: undefined, verifiedVia: undefined } : d)));
    return err("Ownership of this domain could not be proven just now, so nothing was sent to it. Check the DNS record or file is still in place.", 403, { reasons: proof.reasons });
  }
  const set = await store.getFindings(g.repo);
  if (!set) return err("Run a security scan first, then run these checks.", 409);

  const run = await runPassiveChecks(domain, transport);
  if (run.blocked) return err(run.notes[0] ?? "That domain cannot be checked.", 400);

  const key = `passive:${domain}`;
  const now = Date.now();
  const next = refreshTrend({
    ...set,
    findings: [...set.findings.filter((f) => f.detail.source !== key), ...run.findings].sort(byPriority),
    sources: { ...set.sources, [key]: { status: "ok", label: domain, count: run.findings.length, importedAt: now, via: "check", ...(run.notes.length ? { message: run.notes.join(" ") } : {}) } },
  });
  await store.putFindings(g.repo, next);
  await store.putDomains(g.repo, list.map((d) => (d.domain === domain ? { ...d, verifiedAt: now, verifiedVia: proof.via, lastCheckAt: now, lastCheckCount: run.findings.length } : d)));
  return done(Response.json({ checked: true, findings: run.findings.length, requests: run.requests, notes: run.notes }, { headers: NO_STORE }));
}

/** Stop testing a domain: forget it and remove the findings from its checks. */
export async function DELETE(req: Request) {
  const rl = rateLimit(req, LIMITS.domains);
  if (!rl.ok) return tooMany(rl);
  const url = new URL(req.url);
  const g = await gate(req, url.searchParams.get("repo"));
  if (g.fail) return g.fail;
  const parsed = parseDomain(url.searchParams.get("domain") ?? "");
  if (!parsed.ok) return err(parsed.reason, 400);
  const store = persist();
  const list = await store.getDomains(g.repo);
  if (!list.some((d) => d.domain === parsed.domain)) return err("There is no such domain.", 404);
  await store.putDomains(g.repo, list.filter((d) => d.domain !== parsed.domain));
  const set = await store.getFindings(g.repo);
  const key = `passive:${parsed.domain}`;
  if (set) {
    const { [key]: _gone, ...rest } = set.sources ?? {}; // eslint-disable-line @typescript-eslint/no-unused-vars
    await store.putFindings(g.repo, refreshTrend({ ...set, findings: set.findings.filter((f) => f.detail.source !== key), sources: Object.keys(rest).length ? rest : undefined }));
  }
  return withSetCookie(Response.json({ ok: true }, { headers: NO_STORE }), g.a.setCookie);
}
