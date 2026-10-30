export type Tone = "nominal" | "degraded" | "failing" | "unknown";

/** What the background worker tells the page. Never contains a token or anything private beyond the verdict. */
export type Status =
  | { state: "ok"; word: string; tone: Tone; why: string }
  | { state: "unmapped" }
  | { state: "signin" }
  | { state: "unavailable" }
  | { state: "offline" };

export interface View { text: string; tone: Tone; /** shape glyph: colour is never the only signal */ glyph: string; title: string; href: string }

const GLYPH: Record<Tone, string> = { nominal: "✓", degraded: "!", failing: "✕", unknown: "?" };

/** Pure: a status becomes exactly what the button shows and where it goes. */
export function viewOf(status: Status | null, origin: string, repo: string): View {
  const scan = `${origin}/scan?repo=${encodeURIComponent(repo)}`;
  const mk = (text: string, tone: Tone, title: string, href = scan): View => ({ text, tone, glyph: GLYPH[tone], title, href });
  if (!status) return mk("…", "unknown", "Checking launch status");
  switch (status.state) {
    case "ok": return mk(status.word, status.tone, `Launch status: ${status.word}. ${status.why}`);
    case "unmapped": return mk("Map it", "unknown", "Not mapped yet. Open it to build the map.");
    case "signin": return mk("Sign in", "unknown", "Private repository: sign in to Mission Control to see its status.", `${origin}/api/auth/login?returnTo=${encodeURIComponent(`/scan?repo=${repo}`)}`);
    case "offline": return mk("offline", "unknown", "Could not reach Mission Control.");
    default: return mk("n/a", "unknown", "No status available for this repository.");
  }
}
