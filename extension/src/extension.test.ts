import { describe, expect, it } from "vitest";
import { repoFromPath } from "./repo";
import { viewOf } from "./status";

describe("repoFromPath", () => {
  it("finds the repo on the repo page and on any page inside it", () => {
    for (const p of ["/acme/shop", "/acme/shop/", "/acme/shop/issues", "/acme/shop/blob/main/src/a.ts", "/acme/shop/actions/runs/12"]) expect(repoFromPath(p)).toBe("acme/shop");
  });
  it("keeps dots, dashes and a .github repo; drops a .git suffix", () => {
    expect(repoFromPath("/vercel/next.js")).toBe("vercel/next.js");
    expect(repoFromPath("/my-org/my_repo-2")).toBe("my-org/my_repo-2");
    expect(repoFromPath("/acme/.github")).toBe("acme/.github");
    expect(repoFromPath("/acme/shop.git")).toBe("acme/shop");
  });
  it("is null for everything that is not a repository", () => {
    for (const p of ["/", "/acme", "/settings/profile", "/orgs/acme/people", "/marketplace/actions", "/search", "/explore", "/notifications", "/pulls", "/issues", "/sponsors/acme", "/login/oauth"]) expect(repoFromPath(p), p).toBeNull();
  });
  it("rejects hostile or malformed segments", () => {
    for (const p of ["/-bad/repo", "/a b/repo", "/acme/..", "/acme/.", "/%41/repo", "/acme/re<po>", `/${"a".repeat(60)}/repo`]) expect(repoFromPath(p), p).toBeNull();
  });
});

describe("viewOf", () => {
  const O = "https://twin.example";
  it("shows the verdict with a shape and a word, never colour alone", () => {
    const go = viewOf({ state: "ok", word: "GO", tone: "nominal", why: "All monitored systems nominal" }, O, "acme/shop");
    const bad = viewOf({ state: "ok", word: "NO-GO", tone: "failing", why: "CI failing" }, O, "acme/shop");
    expect([go.glyph, go.text, bad.glyph, bad.text]).toEqual(["✓", "GO", "✕", "NO-GO"]);
    expect(bad.title).toContain("CI failing");
    expect(bad.href).toBe("https://twin.example/scan?repo=acme%2Fshop");
  });
  it("every state has a neutral, honest fallback", () => {
    expect(viewOf(null, O, "a/b").text).toBe("…");
    expect(viewOf({ state: "unmapped" }, O, "a/b")).toMatchObject({ text: "Map it", tone: "unknown" });
    expect(viewOf({ state: "offline" }, O, "a/b").text).toBe("offline");
    expect(viewOf({ state: "unavailable" }, O, "a/b").text).toBe("n/a");
  });
  it("a private repo sends you through sign-in and back to the map", () => {
    const v = viewOf({ state: "signin" }, O, "acme/vault");
    expect(v.text).toBe("Sign in");
    expect(v.href).toBe("https://twin.example/api/auth/login?returnTo=%2Fscan%3Frepo%3Dacme%2Fvault");
  });
});
