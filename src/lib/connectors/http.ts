import type { ConnectorCtx } from "./types";

/** GET JSON with a token. Errors carry the status and never the token. */
export async function getJson(ctx: ConnectorCtx, url: string, token: string): Promise<unknown> {
  const res = await ctx.fetch(url, { headers: { authorization: `Bearer ${token}`, accept: "application/json" }, cache: "no-store", signal: AbortSignal.timeout(15_000) });
  if (res.status === 401 || res.status === 403) throw new Error("The token was rejected (check it and its permissions).");
  if (res.status === 429) throw new Error("Rate limited by the provider.");
  if (!res.ok) throw new Error(`The provider returned ${res.status}.`);
  return res.json();
}
