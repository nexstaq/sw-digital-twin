/**
 * Fixed-window limiter, per client, per route. In-memory: each serverless instance counts on its own, so this is a
 * brake on one noisy client, not a global quota. A shared store (or Vercel's WAF rate-limit rule) is the next step.
 */
interface Bucket { count: number; resetAt: number }
const buckets = new Map<string, Bucket>();
/** RATE_LIMIT_SCALE multiplies every limit: headroom for the e2e suite, a looser setting behind a trusted proxy. Default 1. */
const SCALE = Number(process.env.RATE_LIMIT_SCALE) > 0 ? Number(process.env.RATE_LIMIT_SCALE) : 1;
const MAX_KEYS = 10_000;

export interface Limit { name: string; max: number; windowMs: number }
export type Verdict = { ok: true } | { ok: false; retryAfterSec: number };

/** Best-effort client address: the platform sets x-forwarded-for / x-real-ip; "anon" keeps unknown clients in one bucket. */
export function clientKey(req: Request): string {
  const fwd = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return fwd || req.headers.get("x-real-ip") || "anon";
}

export function rateLimit(req: Request, limit: Limit, now = Date.now()): Verdict {
  const key = `${limit.name}:${clientKey(req)}`;
  if (buckets.size > MAX_KEYS) for (const [k, b] of buckets) if (b.resetAt <= now) buckets.delete(k);
  if (buckets.size > MAX_KEYS) buckets.clear(); // under a flood, forget everyone rather than grow without bound
  let b = buckets.get(key);
  if (!b || b.resetAt <= now) { b = { count: 0, resetAt: now + limit.windowMs }; buckets.set(key, b); }
  if (++b.count > limit.max * SCALE) return { ok: false, retryAfterSec: Math.max(1, Math.ceil((b.resetAt - now) / 1000)) };
  return { ok: true };
}

export function tooMany(v: Extract<Verdict, { ok: false }>): Response {
  return Response.json({ error: "Too many requests. Try again shortly." }, { status: 429, headers: { "retry-after": String(v.retryAfterSec) } });
}

/** Same refusal for event-stream endpoints, whose clients parse `data:` lines to show the reason. */
export function tooManySse(v: Extract<Verdict, { ok: false }>): Response {
  const body = `data: ${JSON.stringify({ type: "error", message: "Too many requests. Try again shortly." })}\n\n`;
  return new Response(body, { status: 429, headers: { "content-type": "text/event-stream", "retry-after": String(v.retryAfterSec) } });
}

export const LIMITS = {
  login: { name: "login", max: 20, windowMs: 60_000 },
  scan: { name: "scan", max: 6, windowMs: 60_000 },
  ask: { name: "ask", max: 20, windowMs: 60_000 },
  stream: { name: "stream", max: 20, windowMs: 60_000 },
  otlp: { name: "otlp", max: 120, windowMs: 60_000 },
  shared: { name: "shared", max: 60, windowMs: 60_000 },
  badge: { name: "badge", max: 120, windowMs: 60_000 },
  verdict: { name: "verdict", max: 60, windowMs: 60_000 },
  secscan: { name: "secscan", max: 3, windowMs: 60_000 },
  snippet: { name: "snippet", max: 60, windowMs: 60_000 },
  write: { name: "write", max: 30, windowMs: 60_000 },
} satisfies Record<string, Limit>;

export function resetRateLimits() { buckets.clear(); }
