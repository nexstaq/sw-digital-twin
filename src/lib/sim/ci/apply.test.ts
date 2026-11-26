import { describe, expect, it } from "vitest";
import { FindingSchema } from "@/lib/security/types";
import { accessGraph, shopFindings } from "../range/fixtures";
import { applyReport, type ApplyInput, type Observation } from "./apply";

const SHA = "b".repeat(40);
const URL_ = "https://staging.example.com";
const base = (over: Partial<ApplyInput> = {}): ApplyInput => ({
  url: URL_, profile: "access", sha: SHA, graph: accessGraph(), set: shopFindings(),
  controlStatus: 404, controlBytes: 50, observations: [], authorizedPaths: [], ...over,
});
const OBS = (path: string, status: number, bytes = 2000): Observation => ({ path, status, bytes });

describe("applyReport: only ever scores what was actually authorised", () => {
  it("a reported route that was never on the authorised list is rejected outright, never scored", () => {
    const r = applyReport(base({ observations: [OBS("/api/admin/stats", 200)], authorizedPaths: ["/api/orders"] }));
    expect(r.findings).toEqual([]);
    expect(r.rejected).toBe(1);
    expect(r.accepted).toBe(0);
    expect(r.notes.join(" ")).toMatch(/were not on the list this run authorised/);
  });
  it("an admin route answering 200, unlike a page that does not exist, is a confirmed finding", () => {
    const r = applyReport(base({ observations: [OBS("/api/admin/stats", 200, 2000)], authorizedPaths: ["/api/admin/stats"] }));
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]).toMatchObject({ ruleId: "SIM/anonymous-access", severity: "high", category: "runtime" });
    expect(r.findings[0].path).toBe(`${URL_}/api/admin/stats`);
    expect(r.findings[0].detail.source).toBe("ci-runner");
    expect(FindingSchema.safeParse(r.findings[0]).success).toBe(true);
  });
  it("401, 403, or a redirect is protected: no finding", () => {
    for (const status of [401, 403, 302]) {
      const r = applyReport(base({ observations: [OBS("/api/admin/stats", status)], authorizedPaths: ["/api/admin/stats"] }));
      expect(r.findings, String(status)).toEqual([]);
    }
  });
  it("a site that answers the control path like a real page proves nothing: same-size 200s are inconclusive", () => {
    const r = applyReport(base({ controlStatus: 200, controlBytes: 2000, observations: [OBS("/api/admin/stats", 200, 2010)], authorizedPaths: ["/api/admin/stats"] }));
    expect(r.findings).toEqual([]);
  });
  it("a route the map already says is meant for anyone answering anonymously is not a finding", () => {
    const r = applyReport(base({ observations: [OBS("/api/orders", 200)], authorizedPaths: ["/api/orders"] }));
    expect(r.findings).toEqual([]);
  });
  it("a write route sharing the same path as the GET route being scored never leaks its (different) minRole into the score", () => {
    // /api/orders is both GET (anonymous) and POST (user) on this fixture; scoring the GET must use the GET's own role
    const r = applyReport(base({ observations: [OBS("/api/orders", 200)], authorizedPaths: ["/api/orders"] }));
    expect(r.findings).toEqual([]); // would wrongly become a "medium" finding if the POST route's minRole leaked in
  });
  it("the 'reachability' profile never produces a finding, even for an admin route that answers: it only counts", () => {
    const r = applyReport(base({ profile: "reachability", observations: [OBS("/api/admin/stats", 200), OBS("/api/orders", 200)], authorizedPaths: ["/api/admin/stats", "/api/orders"] }));
    expect(r.findings).toEqual([]);
    expect(r.notes.join(" ")).toMatch(/2 of 2 checked routes answered live/);
  });
  it("nothing reported means nothing found, and it says so", () => {
    const r = applyReport(base());
    expect(r.notes).toContain("Nothing was reported.");
  });
  it("never carries a secret or a response body: only status, byte count and the route", () => {
    const r = applyReport(base({ observations: [OBS("/api/admin/stats", 200, 2000)], authorizedPaths: ["/api/admin/stats"] }));
    const json = JSON.stringify(r.findings);
    expect(json).not.toMatch(/password|authorization:|bearer /i);
  });
});
