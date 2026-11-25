import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { posture, byPriority } from "@/lib/security/map";
import { SimulationSchema, type Finding, type FindingSet } from "@/lib/security/types";
import { verifyChain } from "../audit";
import { KillRegistry } from "../agent/killswitch";
import { applySimulations, verifyFindings, type VerifyInput, type VerifyResult } from "./agent";
import { diskExcerpt } from "./helpers";
import { validateDiff } from "./source";
import { FIXTURE_DIR, fixtureWorld, SHA } from "./world";

const NOW = 1_800_000_000_000;
const verify = async (over: Partial<VerifyInput> = {}) => {
  const { graph, set } = await fixtureWorld();
  const r = await verifyFindings({ repo: "acme/shop", sha: SHA, graph, set, now: () => NOW, ...over });
  return { r, set, graph };
};
const pick = (set: FindingSet, rule: string, file: string): Finding => set.findings.find((f) => f.ruleId === rule && f.path === file)!;
const simOf = (x: { r: VerifyResult; set: FindingSet }, rule: string, file: string) => x.r.simulations[pick(x.set, rule, file).id];

describe("the white-box agent on the fixture repository, with the owner's permission to read source", () => {
  it("confirms the seeded SQL injection and the seeded path traversal", async () => {
    const x = await verify({ excerpt: diskExcerpt });
    expect(simOf(x, "CODE/sql-injection", "app/api/orders/route.ts")).toMatchObject({ verdict: "confirmed", confidence: "high", source: { read: true } });
    expect(simOf(x, "CODE/path-traversal", "app/api/files/route.ts")).toMatchObject({ verdict: "confirmed", confidence: "high", source: { read: true } });
  });

  it("downgrades the seeded false positive: the id is forced to a number before it reaches the query", async () => {
    const x = await verify({ excerpt: diskExcerpt });
    const fp = simOf(x, "CODE/sql-injection", "app/api/invoices/route.ts");
    expect(fp).toMatchObject({ verdict: "mitigated", confidence: "low", source: { read: true } });
    expect(fp.source.mitigation).toMatch(/converted to a number/);
    expect(fp.summary).toMatch(/probably a false alarm/);
    expect(fp.patch).toBeUndefined();
  });

  it("confirms the open write route too, and says what the service behind it can reach", async () => {
    const x = await verify({ excerpt: diskExcerpt });
    const s = simOf(x, "CODE/no-auth-seen", "app/api/orders/route.ts");
    expect(s).toMatchObject({ verdict: "confirmed", test: { role: "anonymous" } });
    expect(s.reaches).toEqual(expect.arrayContaining(["PostgreSQL"]));
    expect(s.summary).toMatch(/not signed in/);
  });

  it("proposes patches as diffs only, and the same test run against a copy without the weakness is refused", async () => {
    const x = await verify({ excerpt: diskExcerpt });
    const sqlId = pick(x.set, "CODE/sql-injection", "app/api/orders/route.ts").id, pathId = pick(x.set, "CODE/path-traversal", "app/api/files/route.ts").id;
    expect(x.r.simulations[sqlId].patch).toEqual({ kind: "parameterise-query", retest: "rejected" });
    expect(x.r.simulations[pathId].patch).toEqual({ kind: "confine-path", retest: "rejected" });
    expect(x.r.patches[sqlId].diff).toBe([
      "--- a/app/api/orders/route.ts", "+++ b/app/api/orders/route.ts", "@@ -2,7 +2,7 @@", " ", " // marks an order as paid", " export async function POST(req: Request) {",
      "-  await db.query(`UPDATE orders SET paid = true WHERE id = ${new URL(req.url).searchParams.get(\"id\")}`);",
      "+  await db.query(\"UPDATE orders SET paid = true WHERE id = $1\", [new URL(req.url).searchParams.get(\"id\")]);",
      "   return Response.json({ ok: true });", " }", " ",
    ].join("\n"));
    expect(x.r.patches[pathId].diff).toContain("+  const body = await readFile(path.join(\"/srv/exports\", path.basename(new URL(req.url).searchParams.get(\"name\") ?? \"\")));");
    for (const [id, p] of Object.entries(x.r.patches)) expect(validateDiff(p.diff, x.set.findings.find((f) => f.id === id)!.path)).toBe(true);
  });

  it("never changes a file: the diffs are text, and the fixture is byte-for-byte as it was", async () => {
    const files = ["app/api/orders/route.ts", "app/api/files/route.ts", "app/api/invoices/route.ts"];
    const before = await Promise.all(files.map((f) => readFile(path.join(FIXTURE_DIR, f), "utf8")));
    await verify({ excerpt: diskExcerpt });
    expect(await Promise.all(files.map((f) => readFile(path.join(FIXTURE_DIR, f), "utf8")))).toEqual(before);
  });

  it("the exploit test is a replayable request sequence, with a baseline, the exploit and a control", async () => {
    const x = await verify({ excerpt: diskExcerpt });
    const t = simOf(x, "CODE/sql-injection", "app/api/orders/route.ts").test!;
    expect(t).toMatchObject({ entry: "POST /api/orders", role: "anonymous", payloadClass: "sqli", technique: "T1190" });
    expect(t.steps.map((s) => s.name)).toEqual(["baseline", "exploit", "control"]);
    expect(t.steps[1].request).toMatchObject({ method: "POST", path: "/api/orders", payloadClass: "sqli" });
    expect(t.steps[2].request.payloadClass).not.toBe("sqli");
  });
});

describe("every claim cites a step of the run's audit log", () => {
  it("each cited step is a real result in the log, and the log verifies against its head", async () => {
    const x = await verify({ excerpt: diskExcerpt });
    const results = new Set(x.r.run.audit.filter((e) => e.kind === "tool-result").map((e) => e.seq));
    for (const [id, s] of Object.entries(x.r.simulations)) {
      expect(s.steps.length, id).toBeGreaterThan(0);
      for (const n of s.steps) expect(results.has(n), `${id} cites step ${n}`).toBe(true);
      expect(s.head).toBe(x.r.run.head);
      expect(s.runId).toBe(x.r.runId);
    }
    expect(verifyChain(x.r.run.audit, { expectedHead: x.r.run.head })).toMatchObject({ ok: true });
  });
  it("each conclusion is in the log, and every request went through the guard: allowed, none refused", async () => {
    const x = await verify({ excerpt: diskExcerpt });
    expect(x.r.run.audit.filter((e) => e.kind === "finding" && e.decision === "allow")).toHaveLength(Object.keys(x.r.simulations).length);
    expect(x.r.run.denies).toEqual({});
    expect(x.r.run.audit.filter((e) => e.kind === "decision").every((e) => e.decision === "allow")).toBe(true);
    expect(x.r.run.stopReason).toBe("finished");
    expect(x.r.run.audit.some((e) => e.kind === "note" && /copy of the range with this weakness removed/.test(e.summary))).toBe(true);
  });
  it("stays inside its rules: range only, one technique, no model, no money", async () => {
    const x = await verify({ excerpt: diskExcerpt });
    expect(x.r.run.audit[0].summary).toMatch(/agent=whitebox.*targets=range/);
    expect(x.r.run.usage).toMatchObject({ tokens: 0, costUsd: 0 });
    expect(new Set(x.r.run.audit.filter((e) => e.kind === "decision").map((e) => e.technique))).toEqual(new Set([undefined, "T1190"]));
  });
});

describe("without permission to read source, it says less and proposes nothing", () => {
  it("the same weaknesses are confirmed only at medium or low confidence, nothing is mitigated, and there are no patches", async () => {
    const x = await verify();
    expect(simOf(x, "CODE/sql-injection", "app/api/orders/route.ts")).toMatchObject({ verdict: "confirmed", confidence: "medium", source: { read: false } });
    expect(simOf(x, "CODE/path-traversal", "app/api/files/route.ts")).toMatchObject({ verdict: "confirmed", confidence: "medium" });
    // the false positive cannot be told apart from a real one without reading the code, and the scanner itself was not sure
    expect(simOf(x, "CODE/sql-injection", "app/api/invoices/route.ts")).toMatchObject({ verdict: "confirmed", confidence: "low" });
    expect(simOf(x, "CODE/sql-injection", "app/api/invoices/route.ts").summary).toMatch(/code was not read/);
    expect(x.r.patches).toEqual({});
    expect(Object.values(x.r.simulations).every((s) => !s.patch && !s.source.read)).toBe(true);
  });
});

describe("what is stored never contains source", () => {
  it("the stored form matches its schema and holds no line of the fixture's code", async () => {
    const x = await verify({ excerpt: diskExcerpt });
    for (const s of Object.values(x.r.simulations)) expect(SimulationSchema.safeParse(s).success).toBe(true);
    const json = JSON.stringify(x.r.simulations) + JSON.stringify(x.r.run.audit);
    for (const code of ["readFile(", "db.query", "SELECT * FROM invoices", "/srv/exports", "Number(new URL", "UPDATE orders", "searchParams"]) expect(json, code).not.toContain(code);
    expect(json).not.toContain("--- a/"); // no diff either: it is returned, not stored
  });
});

describe("what it does not touch", () => {
  it("findings it cannot exercise are returned exactly as they were, and are counted in the notes", async () => {
    const x = await verify({ excerpt: diskExcerpt });
    const merged = applySimulations(x.set, x.r, { sourceRead: true, at: NOW });
    const untouched = x.set.findings.filter((f) => !x.r.simulations[f.id]);
    expect(untouched.length).toBeGreaterThan(0);
    for (const f of untouched) expect(merged.findings.find((m) => m.id === f.id)).toStrictEqual(f); // strictly: not even an added empty field
    expect(x.r.notes.join(" ")).toMatch(/were not exercised/);
  });
  it("severity and the safety score never move: a verdict is evidence, not proof", async () => {
    const x = await verify({ excerpt: diskExcerpt });
    const merged = applySimulations(x.set, x.r, { sourceRead: true, at: NOW });
    expect(posture(merged.findings)).toEqual(posture(x.set.findings));
    for (const f of merged.findings) expect(f.severity).toBe(x.set.findings.find((o) => o.id === f.id)!.severity);
  });
  it("but it does reorder the fix-first list: confirmed up, a likely false alarm down", async () => {
    const x = await verify({ excerpt: diskExcerpt });
    const merged = applySimulations(x.set, x.r, { sourceRead: true, at: NOW });
    const order = (s: FindingSet) => [...s.findings].sort(byPriority).filter((f) => f.ruleId === "CODE/sql-injection").map((f) => f.path);
    expect(order(merged)).toEqual(["app/api/orders/route.ts", "app/api/invoices/route.ts"]);
    const invoices = pick(merged, "CODE/sql-injection", "app/api/invoices/route.ts");
    const others = merged.findings.filter((f) => f.severity === "medium" && f.id !== invoices.id && !f.simulation);
    for (const o of others) expect(byPriority(o, invoices), `${o.ruleId} should now outrank the false alarm`).toBeLessThanOrEqual(0);
  });
  it("records when and how it ran, so the log can be checked later", async () => {
    const x = await verify({ excerpt: diskExcerpt });
    const merged = applySimulations(x.set, x.r, { sourceRead: true, at: NOW });
    expect(merged.simulated).toMatchObject({ at: NOW, runId: x.r.runId, head: x.r.run.head, sourceRead: true, counts: { confirmed: 4, mitigated: 1 } });
  });
});

describe("limits and stopping", () => {
  it("exercises the highest-priority findings first, up to the limit", async () => {
    const x = await verify({ excerpt: diskExcerpt, max: 2 });
    expect(Object.keys(x.r.simulations)).toHaveLength(2);
    const top = [...x.set.findings].sort(byPriority).filter((f) => /CODE\/(sql|path)/.test(f.ruleId)).slice(0, 2).map((f) => f.id);
    expect(Object.keys(x.r.simulations).sort()).toEqual(top.sort());
  });
  it("only the findings asked for", async () => {
    const { set } = await fixtureWorld();
    const id = pick(set, "CODE/path-traversal", "app/api/files/route.ts").id;
    const x = await verify({ only: [id] });
    expect(Object.keys(x.r.simulations)).toEqual([id]);
  });
  it("the kill switch stops it between findings: what was done is kept, the rest is unchanged, and the range is torn down", async () => {
    const reg = new KillRegistry();
    let reads = 0;
    const x = await verify({ killRegistry: reg, excerpt: async (f) => { if (++reads === 2) await reg.killRepo("acme/shop"); return diskExcerpt(f); } });
    expect(x.r.run.stopReason).toBe("killed");
    const done = Object.keys(x.r.simulations).length;
    expect(done).toBeGreaterThanOrEqual(1);
    expect(done).toBeLessThan(4);
    expect(x.r.notes.join(" ")).toMatch(/stopped|ended early/);
    expect(reg.active()).toHaveLength(0);
    expect(x.r.run.audit.some((e) => e.kind === "kill")).toBe(true);
  });
  it("a source reader that fails is the same as not reading source", async () => {
    const x = await verify({ excerpt: async () => { throw new Error("github is down"); } });
    expect(simOf(x, "CODE/sql-injection", "app/api/orders/route.ts")).toMatchObject({ verdict: "confirmed", confidence: "medium", source: { read: false } });
  });
});

describe("a finding the map cannot connect to anything exposed", () => {
  it("is marked unreachable at low confidence, citing the inspection, without sending it any request", async () => {
    const { graph, set } = await fixtureWorld();
    const lonely: Finding = { ...pick(set, "CODE/sql-injection", "app/api/orders/route.ts"), id: "f_lonely", path: "src/server.ts", line: 3 };
    const x = await verify({ graph, set: { ...set, findings: [...set.findings, lonely] }, only: ["f_lonely"] });
    expect(x.r.simulations.f_lonely).toMatchObject({ verdict: "unreachable", confidence: "low", source: { read: false } });
    expect(x.r.simulations.f_lonely.summary).toMatch(/not a clean bill of health/);
    expect(x.r.simulations.f_lonely.steps).toHaveLength(1);
    expect(x.r.run.audit.filter((e) => e.kind === "decision" && e.tool === "range_request")).toHaveLength(0);
  });
});

describe("when one route carries more than one weakness", () => {
  const twin = async (ruleId: string, id: string, line: number) => {
    const { graph, set } = await fixtureWorld();
    const base = pick(set, "CODE/sql-injection", "app/api/orders/route.ts");
    return { graph, set: { ...set, findings: [...set.findings, { ...base, id, ruleId, line, title: `second ${ruleId}`, ...(ruleId === "CODE/command-injection" ? { detail: {} } : {}) }] } };
  };

  it("a second, different weakness in the same file does not sink the first: the control uses a kind the route has no weakness for", async () => {
    const { graph, set } = await twin("CODE/command-injection", "f_cmdi", 5);
    const x = await verify({ graph, set, only: [pick(set, "CODE/sql-injection", "app/api/orders/route.ts").id, "f_cmdi"] });
    expect(x.r.simulations[pick(set, "CODE/sql-injection", "app/api/orders/route.ts").id]).toMatchObject({ verdict: "confirmed" });
    expect(x.r.simulations.f_cmdi).toMatchObject({ verdict: "confirmed" });
    for (const s of Object.values(x.r.simulations)) {
      const used = s.test!.steps.map((t) => t.request.payloadClass);
      expect(new Set(used.filter(Boolean)).size).toBe(2); // the exploit's class and a different control class
      expect(["sqli", "cmdi"]).not.toContain(s.test!.steps[2].request.payloadClass); // the control is neither of the route's own weaknesses
    }
  });

  it("a patch that removes only one of two identical weaknesses is reported as still exploitable: the retest can fail", async () => {
    const { graph, set } = await twin("CODE/sql-injection", "f_dup", 5);
    const x = await verify({ graph, set, excerpt: diskExcerpt, only: [pick(set, "CODE/sql-injection", "app/api/orders/route.ts").id, "f_dup"] });
    const sims = Object.values(x.r.simulations);
    expect(sims).toHaveLength(2);
    for (const s of sims) expect(s.patch).toEqual({ kind: "parameterise-query", retest: "still-exploited" });
  });
});

describe("it is repeatable", () => {
  it("the same inputs give the same verdicts and the same log head", async () => {
    const [a, b] = [await verify({ excerpt: diskExcerpt }), await verify({ excerpt: diskExcerpt })];
    expect(a.r.simulations).toEqual(b.r.simulations);
    expect(a.r.run.head).toBe(b.r.run.head);
  });
});
