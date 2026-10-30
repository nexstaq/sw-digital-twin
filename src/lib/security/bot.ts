import { checkBotId } from "botid/server";

export interface BotVerdict { isBot: boolean }

/**
 * Vercel BotID gate for the expensive routes (scan clones a repo, ask spends model tokens).
 * Returns a 403 Response for a bot, otherwise null. BotID only exists on Vercel, so elsewhere (dev, self-host, CI) it is off.
 * If the check itself errors we let the request through: a BotID outage must not take the product down, and the per-client
 * rate limits still apply.
 */
export async function denyBots(o: { check?: () => Promise<BotVerdict>; enabled?: boolean } = {}): Promise<Response | null> {
  const enabled = o.enabled ?? !!process.env.VERCEL;
  if (!enabled) return null;
  try {
    const v = await (o.check ?? checkBotId)();
    if (v.isBot) return Response.json({ error: "Automated traffic isn't allowed here." }, { status: 403, headers: { "cache-control": "no-store" } });
  } catch (e) {
    console.error("botid check failed; allowing request", e instanceof Error ? e.message : e);
  }
  return null;
}
