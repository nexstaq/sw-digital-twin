import { poke } from "@/lib/github/bus";
import { repoOfEvent, verifySignature } from "@/lib/github/webhook";

export const maxDuration = 10;

/** GitHub App / repo webhook receiver. Verifies the signature, then tells live streams to refresh. Holds no state itself. */
export async function POST(req: Request) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) return Response.json({ error: "Webhook receiver is not configured." }, { status: 503 });

  const raw = await req.text();
  if (!verifySignature(secret, raw, req.headers.get("x-hub-signature-256"))) {
    return Response.json({ error: "Bad signature." }, { status: 401 });
  }

  const event = req.headers.get("x-github-event");
  if (event === "ping") return Response.json({ ok: true, pong: true });

  let payload: unknown;
  try { payload = JSON.parse(raw); } catch { return Response.json({ error: "Invalid JSON." }, { status: 400 }); }

  const repo = repoOfEvent(event, payload);
  if (!repo) return Response.json({ ok: true, ignored: true }, { status: 202 });
  poke(repo);
  return Response.json({ ok: true, repo }, { status: 202 });
}
