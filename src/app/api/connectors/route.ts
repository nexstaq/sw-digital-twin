import { collect } from "@/lib/connectors/collect";
import { parseRepo } from "@/lib/ingest/repo";

export const maxDuration = 30;

/** Which connectors are on for this repo, and what each one could map to nodes. No telemetry values, only names. */
export async function GET(req: Request) {
  let repo: string;
  try { const r = parseRepo(new URL(req.url).searchParams.get("repo") ?? ""); repo = `${r.owner}/${r.name}`.toLowerCase(); } catch (e) {
    return Response.json({ error: (e as Error).message }, { status: 400 });
  }
  const c = await collect(repo);
  return Response.json({ status: c.status, targets: c.targets });
}
