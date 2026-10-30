import { describe, expect, it } from "vitest";
import { analyzeExposure } from "./exposure";
import type { SecurityContext } from "../types";

const ctx = (files: Record<string, string>): SecurityContext => ({ repo: "a/b", files: Object.keys(files), read: async (p) => files[p] ?? null });
const run = (files: Record<string, string>, endpoints: string[]) => analyzeExposure(ctx(files), endpoints);

const WRITE = "export async function POST(req: Request) { await db.insert(x); return Response.json({}); }";
const READ = "export async function GET() { return Response.json({}); }";

describe("analyzeExposure", () => {
  it("flags an endpoint that accepts writes with no authentication check, as a LOW, low-confidence note", async () => {
    const r = await run({ "app/api/orders/route.ts": WRITE }, ["app/api/orders/route.ts"]);
    expect(r.exposure).toMatchObject({ endpointFiles: 1, unauthenticatedWrites: ["app/api/orders/route.ts"], middlewareAuth: false });
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ ruleId: "CODE/no-auth-seen", severity: "low", confidence: "low", cwe: ["CWE-306"], path: "app/api/orders/route.ts" });
    expect(r.findings[0].reason).toContain("false alarm"); // it says plainly that it can be wrong
  });
  it("does not flag read-only endpoints, or endpoints that check the caller", async () => {
    const r = await run({
      "app/api/a/route.ts": READ,
      "app/api/b/route.ts": `import { getServerSession } from "next-auth";\n${WRITE}`,
      "app/api/c/route.ts": `${WRITE}\n// if (!user) return new Response("no", { status: 401 })`,
      "api/d.py": "@app.post('/x')\n@login_required\ndef x(): pass",
    }, ["app/api/a/route.ts", "app/api/b/route.ts", "app/api/c/route.ts", "api/d.py"]);
    expect(r.findings).toEqual([]);
    expect(r.exposure.unauthenticatedWrites).toEqual([]);
  });
  it("a project-wide auth middleware counts as the check for every endpoint, so it stays quiet", async () => {
    const r = await run({ "middleware.ts": "import { auth } from './auth';\nexport default auth((req) => { if (!req.auth) return Response.redirect('/login'); });", "app/api/orders/route.ts": WRITE }, ["app/api/orders/route.ts"]);
    expect(r.exposure.middlewareAuth).toBe(true);
    expect(r.findings).toEqual([]);
  });
  it("recognises the common ways frameworks spell it", async () => {
    for (const mw of ["export { auth as middleware } from '@/auth';", "export default clerkMiddleware();", "export default authMiddleware({});", "export default withAuth(function mw() {});", "export function middleware(req) { return req.auth ? next() : redirect(); }"]) {
      const r = await run({ "middleware.ts": mw, "app/api/o/route.ts": WRITE }, ["app/api/o/route.ts"]);
      expect(r.exposure.middlewareAuth, mw).toBe(true);
    }
  });
  it("a middleware with no auth in it does not excuse anything", async () => {
    const r = await run({ "middleware.ts": "export function middleware() { return NextResponse.next(); }", "app/api/orders/route.ts": WRITE }, ["app/api/orders/route.ts"]);
    expect(r.exposure.middlewareAuth).toBe(false);
    expect(r.findings).toHaveLength(1);
  });
  it("caps the number of findings so one big repo cannot flood the list, but still counts every file", async () => {
    const files: Record<string, string> = {};
    for (let i = 0; i < 50; i++) files[`app/api/r${i}/route.ts`] = WRITE;
    const r = await run(files, Object.keys(files));
    expect(r.findings).toHaveLength(30);
    expect(r.exposure.unauthenticatedWrites).toHaveLength(50);
  });
  it("ids are stable and it ignores files it cannot read", async () => {
    const a = await run({ "r.ts": WRITE }, ["r.ts", "missing.ts"]);
    const b = await run({ "r.ts": `// new comment\n${WRITE}` }, ["r.ts"]);
    expect(a.findings[0].id).toBe(b.findings[0].id);
    expect(a.exposure.unauthenticatedWrites).toEqual(["r.ts"]);
  });
});
