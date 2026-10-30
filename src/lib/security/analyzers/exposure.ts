import type { Finding, FindingSet, SecurityContext } from "../types";
import { fingerprint } from "../util";

type Exposure = NonNullable<FindingSet["exposure"]>;

/** Words that mean "this code checks who is calling". A heuristic: it can miss a custom check, so it only ever raises a LOW, low-confidence note. */
const AUTH = /\b(getServerSession|getSession|getToken|auth\s*\(|auth as middleware|authMiddleware|clerkMiddleware|req(?:uest)?\.auth|currentUser|requireAuth|requireUser|requireSession|withAuth|authorize|authenticate|isAuthenticated|ensureLoggedIn|checkAuth|assertAuth|verifyToken|verifyJwt|jwt\.verify|passport\.authenticate|NextAuth|authjs|clerk|auth0|supabase\.auth|session\.user|bearer|Authorization|login_required|jwt_required|Depends\(\s*get_current_user|HTTPBearer|OAuth2PasswordBearer|permission_classes|IsAuthenticated)\b|Unauthorized|\b401\b/i;
/** Request handlers that change state. */
const WRITES = /export\s+(?:async\s+)?function\s+(?:POST|PUT|PATCH|DELETE)\b|export\s+const\s+(?:POST|PUT|PATCH|DELETE)\b|\.(?:post|put|patch|delete)\s*\(|@(?:app|router|bp)\.(?:post|put|patch|delete)\b|methods\s*=\s*\[[^\]]*['"](?:POST|PUT|PATCH|DELETE)['"]|req(?:uest)?\.method\s*===?\s*['"](?:POST|PUT|PATCH|DELETE)['"]/i;
const MIDDLEWARE = /(^|\/)(middleware|proxy)\.[jt]sx?$/;

/**
 * Which endpoint files accept writes with no authentication check in sight? A project-wide auth middleware counts as a check
 * for everything, since that is where Next.js and Express apps usually put it.
 */
export async function analyzeExposure(ctx: SecurityContext, endpointFiles: string[]): Promise<{ exposure: Exposure; findings: Finding[] }> {
  let middlewareAuth = false;
  for (const f of ctx.files.filter((p) => MIDDLEWARE.test(p))) { const t = await ctx.read(f); if (t && AUTH.test(t)) { middlewareAuth = true; break; } }

  const unauthenticatedWrites: string[] = [];
  const findings: Finding[] = [];
  for (const path of [...new Set(endpointFiles)].slice(0, 600)) {
    const text = await ctx.read(path);
    if (!text) continue;
    if (!WRITES.test(text) || middlewareAuth || AUTH.test(text)) continue;
    unauthenticatedWrites.push(path);
    if (findings.length < 30) {
      findings.push({
        id: fingerprint("code", path, "CODE/no-auth-seen"), ruleId: "CODE/no-auth-seen", category: "code", severity: "low", confidence: "low",
        title: "Endpoint accepts writes and shows no authentication check", path, line: 1,
        reason: "This route changes data, and neither it nor any project-wide middleware appears to check who is calling. If authentication happens somewhere this scan cannot see (an API gateway, a wrapper, an edge rule), this is a false alarm; if not, anyone on the internet can call it.",
        fix: "Check the caller at the top of the handler (or in middleware) and reject with 401 before doing anything else. If the route is intentionally public, say so in a comment and make sure it validates its input and is rate limited.",
        cwe: ["CWE-306"], owasp: "A01:2021 Broken Access Control", detail: {},
      });
    }
  }
  return { exposure: { endpointFiles: new Set(endpointFiles).size, unauthenticatedWrites, middlewareAuth }, findings };
}
