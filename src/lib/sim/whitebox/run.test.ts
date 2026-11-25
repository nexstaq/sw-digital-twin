import { describe, expect, it, vi } from "vitest";
import type { FindingSet } from "@/lib/security/types";
import { diskExcerpt } from "./helpers";
import { patchFor, simulateAndStore, type SimDeps } from "./run";
import { fixtureWorld, SHA } from "./world";

const NOW = 1_800_000_000_000;

async function rig(over: { findings?: FindingSet | null; snapshotSha?: string | null } = {}) {
  const { graph, set } = await fixtureWorld();
  let stored: FindingSet | null = over.findings === undefined ? set : over.findings;
  const put = vi.fn(async (_r: string, s: FindingSet) => { stored = s; });
  const read = vi.fn(async (...a: [string, string, string, number | undefined, string | undefined]) => diskExcerpt({ path: a[2], line: a[3] } as never));
  const snapSha = over.snapshotSha === undefined ? SHA : over.snapshotSha;
  const deps: SimDeps = {
    store: {
      getFindings: async () => stored, putFindings: put,
      listSnapshots: async () => (snapSha ? [{ sha: snapSha, createdAt: 1 }] : []),
      getSnapshot: async () => (snapSha ? { sha: snapSha, createdAt: 1, graph } : null),
    },
    excerpt: read as never, now: () => NOW,
  };
  return { deps, put, read, stored: () => stored, set };
}

describe("verify by simulation, for one repository", () => {
  it("needs a scan and a map first, and says which is missing", async () => {
    expect(await simulateAndStore("acme/shop", "t", { source: false, deps: (await rig({ findings: null })).deps })).toMatchObject({ ok: false, status: 409, error: expect.stringMatching(/scan first/) });
    expect(await simulateAndStore("acme/shop", "t", { source: false, deps: (await rig({ snapshotSha: null })).deps })).toMatchObject({ ok: false, status: 409, error: expect.stringMatching(/Map the repository first/) });
  });

  it("stores the verdicts on the findings and when it ran, and changes nothing else about them", async () => {
    const r = await rig();
    const out = await simulateAndStore("acme/shop", "t", { source: false, deps: r.deps });
    expect(out.ok).toBe(true);
    expect(r.put).toHaveBeenCalledTimes(1);
    const saved = r.stored()!;
    expect(saved.simulated).toMatchObject({ at: NOW, sourceRead: false });
    expect(saved.findings.filter((f) => f.simulation).length).toBeGreaterThan(0);
    for (const f of saved.findings) { const { simulation: _s, ...rest } = f; const before = r.set.findings.find((o) => o.id === f.id)!; expect(rest).toEqual(before); } // eslint-disable-line @typescript-eslint/no-unused-vars
  });

  it("does not read a line of source unless asked, and then only for the findings it exercises, with the caller's token", async () => {
    const off = await rig();
    await simulateAndStore("acme/shop", "tok", { source: false, deps: off.deps });
    expect(off.read).not.toHaveBeenCalled();
    expect(off.stored()!.simulated!.sourceRead).toBe(false);

    const on = await rig();
    await simulateAndStore("acme/shop", "tok", { source: true, deps: on.deps });
    expect(on.stored()!.simulated!.sourceRead).toBe(true);
    const paths = new Set(on.read.mock.calls.map((c) => c[2]));
    expect(paths).toEqual(new Set(["app/api/orders/route.ts", "app/api/files/route.ts", "app/api/invoices/route.ts"]));
    expect(on.read.mock.calls.every((c) => c[1] === SHA && c[4] === "tok")).toBe(true);
  });

  it("stores no source: not a line of the code, and no diff", async () => {
    const r = await rig();
    await simulateAndStore("acme/shop", "t", { source: true, deps: r.deps });
    const json = JSON.stringify(r.stored()!.findings.map((f) => f.simulation)) + JSON.stringify(r.stored()!.simulated);
    for (const code of ["readFile(", "db.query", "SELECT * FROM invoices", "/srv/exports", "UPDATE orders", "--- a/"]) expect(json, code).not.toContain(code);
  });

  it("says when the map and the scan are from different commits", async () => {
    const r = await rig({ snapshotSha: "a".repeat(40) });
    await simulateAndStore("acme/shop", "t", { source: false, deps: r.deps });
    expect(r.stored()!.simulated!.notes[0]).toMatch(/different commits/);
  });

  it("running it again replaces the earlier verdicts rather than piling them up", async () => {
    const r = await rig();
    await simulateAndStore("acme/shop", "t", { source: false, deps: r.deps });
    const first = r.stored()!.findings.filter((f) => f.simulation).length;
    await simulateAndStore("acme/shop", "t", { source: true, deps: r.deps });
    expect(r.stored()!.findings.filter((f) => f.simulation).length).toBe(first);
    expect(r.stored()!.findings.find((f) => f.path === "app/api/invoices/route.ts" && f.ruleId === "CODE/sql-injection")!.simulation!.verdict).toBe("mitigated");
  });
});

describe("the patch, made again on request", () => {
  const withRun = async () => { const r = await rig(); await simulateAndStore("acme/shop", "t", { source: true, deps: r.deps }); r.put.mockClear(); return r; };
  const id = (r: Awaited<ReturnType<typeof rig>>, rule: string, file: string) => r.stored()!.findings.find((f) => f.ruleId === rule && f.path === file)!.id;

  it("returns the diff for a finding the simulation proposed one for, and stores nothing", async () => {
    const r = await withRun();
    const out = await patchFor("acme/shop", id(r, "CODE/path-traversal", "app/api/files/route.ts"), "t", { deps: r.deps });
    expect(out).toMatchObject({ ok: true, kind: "confine-path", retest: "rejected", diff: expect.stringContaining("path.basename(") });
    expect(r.put).not.toHaveBeenCalled();
  });
  it("is only available if the simulation was allowed to read source", async () => {
    const r = await rig();
    await simulateAndStore("acme/shop", "t", { source: false, deps: r.deps });
    expect(await patchFor("acme/shop", id(r, "CODE/path-traversal", "app/api/files/route.ts"), "t", { deps: r.deps })).toMatchObject({ ok: false, status: 409, error: expect.stringMatching(/read source/) });
  });
  it("says so for a finding with no patch, an unknown finding, and a file it cannot read now", async () => {
    const r = await withRun();
    expect(await patchFor("acme/shop", id(r, "CODE/sql-injection", "app/api/invoices/route.ts"), "t", { deps: r.deps })).toMatchObject({ ok: false, status: 404, error: expect.stringMatching(/No patch/) });
    expect(await patchFor("acme/shop", "nope", "t", { deps: r.deps })).toMatchObject({ ok: false, status: 404 });
    const unreadable: SimDeps = { ...r.deps, excerpt: (async () => null) as never };
    expect(await patchFor("acme/shop", id(r, "CODE/path-traversal", "app/api/files/route.ts"), "t", { deps: unreadable })).toMatchObject({ ok: false, status: 404, error: expect.stringMatching(/Could not read/) });
  });
  it("is made again from the file as it is now: if the code changed, the diff changes", async () => {
    const r = await withRun();
    const changed: SimDeps = { ...r.deps, excerpt: (async (_a: string, _b: string, path: string, line: number) => ({ path, startLine: line, lines: ["  return readFile(somethingElse);"] })) as never };
    expect(await patchFor("acme/shop", id(r, "CODE/path-traversal", "app/api/files/route.ts"), "t", { deps: changed })).toMatchObject({ ok: false, status: 404, error: expect.stringMatching(/could not be made again/) });
  });
});
