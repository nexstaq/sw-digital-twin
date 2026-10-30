import { secureCookies } from "@/lib/auth/origin";
import { clearCookie, SESSION_COOKIE } from "@/lib/auth/session";

/** POST only: a cross-site page cannot sign you out (SameSite=Lax cookies are not sent on cross-site POST). */
export async function POST(req: Request) {
  return new Response(null, { status: 204, headers: { "set-cookie": clearCookie(SESSION_COOKIE, secureCookies(req)), "cache-control": "no-store" } });
}
