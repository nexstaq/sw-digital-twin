import { listRepos } from "@/lib/auth/github";
import { viewerOf, withSetCookie } from "@/lib/auth/viewer";

export const maxDuration = 30;

/** The signed-in user's repositories that the GitHub App can see (public and private), for the picker. */
export async function GET(req: Request) {
  const v = await viewerOf(req);
  if (!v) return Response.json({ error: "Sign in with GitHub first." }, { status: 401 });
  try {
    return withSetCookie(Response.json({ repos: await listRepos(v.session.token) }, { headers: { "cache-control": "no-store" } }), v.setCookie);
  } catch {
    return Response.json({ error: "Could not list your repositories from GitHub." }, { status: 502 });
  }
}
