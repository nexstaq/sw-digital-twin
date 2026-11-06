import { timingSafeEqual } from "node:crypto";
import { runDueRescans } from "@/lib/security/schedule/rescan";

export const maxDuration = 300;

const same = (a: string, b: string) => a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));

/**
 * Called by Vercel Cron once a day (see vercel.json). Vercel sends `Authorization: Bearer $CRON_SECRET`. With no CRON_SECRET set the
 * route refuses everyone: an open endpoint that clones repositories would be an abuse vector.
 */
export async function GET(req: Request) {
  const secret = process.env.CRON_SECRET;
  if (!secret) return Response.json({ error: "Scheduled scans are not configured." }, { status: 503 });
  const given = req.headers.get("authorization") ?? "";
  if (!same(given, `Bearer ${secret}`)) return Response.json({ error: "Unauthorized." }, { status: 401 });
  const report = await runDueRescans(Date.now() + 290_000);
  return Response.json(report, { headers: { "cache-control": "no-store" } });
}
