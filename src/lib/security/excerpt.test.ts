import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchExcerpt } from "./excerpt";

const FILE = ["a", "b", "c", "d", "e", "f", "g", "h"].join("\n");
const mockFetch = (status = 200, body = FILE) => vi.spyOn(globalThis, "fetch").mockImplementation((async () => new Response(body, { status })) as never);
afterEach(() => vi.restoreAllMocks());

describe("reading a few lines of one file", () => {
  it("returns the lines around the one asked for, numbered from where the excerpt starts", async () => {
    mockFetch();
    expect(await fetchExcerpt("acme/shop", "a".repeat(40), "src/x.ts", 4, "tok", { span: 2 })).toEqual({ path: "src/x.ts", startLine: 2, lines: ["b", "c", "d", "e", "f"] });
  });
  it("accepts the brackets and parentheses that framework file names contain, and encodes them in the request", async () => {
    const f = mockFetch();
    for (const path of ["app/api/orders/[id]/route.ts", "app/(shop)/page.tsx", "pages/[...slug].tsx"]) expect(await fetchExcerpt("acme/shop", "a".repeat(40), path, 3, undefined), path).not.toBeNull();
    expect(String(f.mock.calls[0][0])).toContain("app/api/orders/%5Bid%5D/route.ts");
  });
  it.each(["../etc/passwd", "a/../b.ts", "/etc/passwd", "./x.ts", "a b/../../c", "x;rm.ts", "x\\y.ts", "x?y.ts", "x#y.ts", "x$(id).ts", "a".repeat(301)])("refuses %j without asking GitHub", async (path) => {
    const f = mockFetch();
    expect(await fetchExcerpt("acme/shop", "a".repeat(40), path, 3, "tok")).toBeNull();
    expect(f).not.toHaveBeenCalled();
  });
  it("sends the caller's token, never anyone else's, and says nothing when there is none", async () => {
    const f = mockFetch();
    await fetchExcerpt("acme/shop", "a".repeat(40), "x.ts", 2, "caller-token");
    await fetchExcerpt("acme/shop", "a".repeat(40), "x.ts", 2, undefined);
    expect((f.mock.calls[0][1] as { headers: Record<string, string> }).headers.authorization).toBe("Bearer caller-token");
    expect((f.mock.calls[1][1] as { headers: Record<string, string> }).headers.authorization).toBeUndefined();
  });
  it.each([0, -1, 1.5, NaN, 2_000_000, undefined])("refuses the line number %j", async (line) => { mockFetch(); expect(await fetchExcerpt("a/b", "s", "x.ts", line as never, "t")).toBeNull(); });
  it("is null, never an error, when GitHub says no, fails, or the line is past the end", async () => {
    mockFetch(404);
    expect(await fetchExcerpt("a/b", "s", "x.ts", 2, "t")).toBeNull();
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network"));
    expect(await fetchExcerpt("a/b", "s", "x.ts", 2, "t")).toBeNull();
    mockFetch();
    expect(await fetchExcerpt("a/b", "s", "x.ts", 99, "t")).toBeNull();
  });
  it("redacts anything that looks like a secret on the way in", async () => {
    const key = "AKIA" + "IOSFODNN7EXAMPLE"; // assembled at run time so no key-shaped string is committed
    mockFetch(200, `const a = 1;\nconst k = "${key}";\nconst b = 2;`);
    const x = await fetchExcerpt("a/b", "s", "x.ts", 2, "t");
    expect(JSON.stringify(x)).not.toContain(key);
    expect(JSON.stringify(x)).toContain("redacted");
  });
});
