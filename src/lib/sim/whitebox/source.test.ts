import { describe, expect, it } from "vitest";
import { parseRoe } from "../roe";
import { scope } from "./test-scope";
import { checkMitigation, proposePatch, validateDiff, type Excerpt } from "./source";
import { whiteboxRoe, WHITEBOX_TECHNIQUE } from "./roe";

const ex = (lines: string[], startLine = 1, path = "app/api/x/route.ts"): Excerpt => ({ path, startLine, lines });
const sqlAt = (lines: string[]) => lines.findIndex((l) => /query\(/.test(l)) + 1;

describe("looking for a visible mitigation", () => {
  const sql = (above: string[], query = "  const rows = await db.query(`SELECT * FROM t WHERE id = ${id}`);") => { const lines = [...above, query]; return checkMitigation("CODE/sql-injection", sqlAt(lines), ex(lines)); };

  it.each([
    ["Number()", ["  const id = Number(new URL(req.url).searchParams.get('id'));"]],
    ["parseInt()", ["  const id = parseInt(params.id, 10);"]],
    ["parseFloat()", ["  const id = parseFloat(params.id);"]],
    ["Math.floor()", ["  let id = Math.floor(q.n);"]],
    ["a unary plus", ["  const id = +params.id;"]],
    ["an integer check", ["  const id = params.id;", "  if (!Number.isInteger(id)) return bad();"]],
    ["a digits-only test", ["  const id = params.id;", "  if (!/^\\d+$/.test(id)) return bad();"]],
  ])("sees %s before the query as a mitigation", (_n, above) => { expect(sql(above)).toMatchObject({ mitigated: true, why: expect.stringContaining("converted to a number") }); });

  it("does not, when the value comes straight from the request", () => { expect(sql(["  const id = new URL(req.url).searchParams.get('id');"])).toEqual({ mitigated: false }); });
  it("does not, when only some of the inserted values are made safe", () => {
    expect(sql(["  const a = Number(x);", "  const b = req.query.b;"], "  await db.query(`SELECT * FROM t WHERE a = ${a} AND b = ${b}`);")).toEqual({ mitigated: false });
  });
  it("sees every inserted value being made safe", () => {
    const r = sql(["  const a = Number(x);", "  const b = Number(y);"], "  await db.query(`SELECT * FROM t WHERE a = ${a} AND b = ${b}`);");
    expect(r).toMatchObject({ mitigated: true, why: expect.stringMatching(/a, b are converted/) });
  });
  it("only counts what comes BEFORE the query: a conversion afterwards protects nothing", () => {
    const lines = ["  const rows = await db.query(`SELECT * FROM t WHERE id = ${id}`);", "  const id = Number(x);"];
    expect(checkMitigation("CODE/sql-injection", 1, ex(lines))).toEqual({ mitigated: false });
  });
  it("only counts what is close by: a conversion far above is not trusted", () => {
    const far = ["  const id = Number(x);", ...Array.from({ length: 20 }, () => "  // filler"), "  await db.query(`SELECT ${id}`);"];
    expect(checkMitigation("CODE/sql-injection", far.length, ex(far))).toEqual({ mitigated: false });
  });
  it("cannot say anything about SQL built by concatenation, and says not mitigated", () => {
    const lines = ["  const id = Number(x);", '  await db.query("SELECT * FROM t WHERE id = " + id);'];
    expect(checkMitigation("CODE/sql-injection", 2, ex(lines))).toEqual({ mitigated: false });
  });
  it("uses the real line numbers of the excerpt, wherever it starts", () => {
    const lines = ["  const id = Number(x);", "  await db.query(`SELECT ${id}`);"];
    expect(checkMitigation("CODE/sql-injection", 41, ex(lines, 40))).toMatchObject({ mitigated: true });
    expect(checkMitigation("CODE/sql-injection", 1, ex(lines, 40))).toEqual({ mitigated: false }); // a line that is not in the excerpt
  });

  it.each([
    ["basename", ["  const f = path.basename(name);", "  return readFile(path.join(base, f));"], "basename"],
    ["a check for ..", ["  if (name.includes('..')) return bad();", "  return readFile(path.join(base, name));"], "rejected"],
    ["a resolved path checked against the folder", ["  const p = path.resolve(base, name);", "  if (!p.startsWith(base)) return bad();", "  return readFile(p);"], "inside the allowed folder"],
  ])("sees %s as confining a file path", (_n, lines, why) => { expect(checkMitigation("CODE/path-traversal", 1, ex(lines))).toMatchObject({ mitigated: true, why: expect.stringContaining(why) }); });
  it("does not, when the name goes straight to the file system", () => { expect(checkMitigation("CODE/path-traversal", 1, ex(["  return readFile(path.join(base, name));"]))).toEqual({ mitigated: false }); });
  it("says nothing for a kind of finding it does not know how to check", () => { expect(checkMitigation("CODE/ssrf", 1, ex(["fetch(url)"]))).toEqual({ mitigated: false }); });
});

describe("proposing a patch", () => {
  const patchFor = (rule: string, line: string, path = "app/api/x/route.ts") => proposePatch(rule, 2, ex(["// above", line, "// below"], 1, path));
  const changed = (p: { diff: string } | null) => ({ minus: p?.diff.split("\n").filter((l) => l.startsWith("-") && !l.startsWith("---")), plus: p?.diff.split("\n").filter((l) => l.startsWith("+") && !l.startsWith("+++")) });

  it("rewrites SQL in a template string into placeholders and a list of values", () => {
    const p = patchFor("CODE/sql-injection", "  await db.query(`SELECT * FROM t WHERE a = ${a} AND b = ${req.query.b}`);");
    expect(p?.kind).toBe("parameterise-query");
    expect(changed(p).plus).toEqual(['+  await db.query("SELECT * FROM t WHERE a = $1 AND b = $2", [a, req.query.b]);']);
  });
  it("handles a value that contains braces and calls", () => {
    const p = patchFor("CODE/sql-injection", "  await db.query(`DELETE FROM t WHERE id = ${fn({ x: 1 }, 2)}`);");
    expect(changed(p).plus).toEqual(['+  await db.query("DELETE FROM t WHERE id = $1", [fn({ x: 1 }, 2)]);']);
  });
  it("escapes quotes in the SQL", () => {
    const p = patchFor("CODE/sql-injection", "  await db.query(`SELECT 'a' FROM t WHERE id = ${id}`);");
    expect(changed(p).plus).toEqual([`+  await db.query("SELECT 'a' FROM t WHERE id = $1", [id]);`]);
  });
  it("keeps whatever follows the call on the line", () => {
    const p = patchFor("CODE/sql-injection", "  const rows = await db.query(`SELECT ${id}`).then(first);");
    expect(changed(p).plus).toEqual(['+  const rows = await db.query("SELECT $1", [id]).then(first);']);
  });
  it("also works for .execute(", () => { expect(patchFor("CODE/sql-injection", "  await conn.execute(`SELECT ${id}`);")?.kind).toBe("parameterise-query"); });

  it("wraps the request-driven part of path.join in basename, leaving the base alone", () => {
    const p = patchFor("CODE/path-traversal", '  const body = await readFile(path.join("/srv/exports", new URL(req.url).searchParams.get("name") ?? ""));');
    expect(p?.kind).toBe("confine-path");
    expect(changed(p).plus).toEqual(['+  const body = await readFile(path.join("/srv/exports", path.basename(new URL(req.url).searchParams.get("name") ?? "")));']);
  });
  it("copes with a comma inside a nested call, and several request-driven parts", () => {
    const p = patchFor("CODE/path-traversal", "  readFile(path.join(base, fn(a, b), req.query.name, req.query.sub));");
    expect(changed(p).plus).toEqual(["+  readFile(path.join(base, fn(a, b), path.basename(req.query.name), path.basename(req.query.sub)));"]);
  });

  it.each([
    ["SQL built by concatenation", "CODE/sql-injection", '  await db.query("SELECT " + id);'],
    ["a template with nothing inserted", "CODE/sql-injection", "  await db.query(`SELECT 1`);"],
    ["an unbalanced insertion", "CODE/sql-injection", "  await db.query(`SELECT ${id`);"],
    ["a call that is not a query", "CODE/sql-injection", "  await log(`SELECT ${id}`);"],
    ["a path already confined", "CODE/path-traversal", "  readFile(path.join(base, path.basename(req.query.name)));"],
    ["a path with nothing from the request", "CODE/path-traversal", "  readFile(path.join(base, name));"],
    ["something that is not path.join", "CODE/path-traversal", "  readFile(base + req.query.name);"],
    ["a kind of finding it has no template for", "CODE/ssrf", "  await fetch(req.query.url);"],
  ])("proposes nothing for %s", (_n, rule, line) => { expect(patchFor(rule, line)).toBeNull(); });
  it("proposes nothing for a language it does not handle, or when the line is not in the excerpt", () => {
    expect(patchFor("CODE/sql-injection", "  db.query(`SELECT ${id}`)", "app/x.py")).toBeNull();
    expect(proposePatch("CODE/sql-injection", 99, ex(["  db.query(`SELECT ${id}`)"]))).toBeNull();
  });

  it("makes a well-formed unified diff: the counts in the header match the body", () => {
    const p = patchFor("CODE/sql-injection", "  await db.query(`SELECT ${id}`);")!;
    const [, , hunk, ...body] = p.diff.split("\n");
    const m = /^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(hunk)!;
    expect(Number(m[2])).toBe(body.filter((l) => l.startsWith(" ") || l.startsWith("-")).length);
    expect(Number(m[4])).toBe(body.filter((l) => l.startsWith(" ") || l.startsWith("+")).length);
    expect(p.diff.startsWith("--- a/app/api/x/route.ts\n+++ b/app/api/x/route.ts\n")).toBe(true);
  });
  it("never edits anything: the excerpt it was given is unchanged", () => {
    const x = ex(["// above", "  await db.query(`SELECT ${id}`);", "// below"]);
    const copy = structuredClone(x);
    proposePatch("CODE/sql-injection", 2, x);
    expect(x).toEqual(copy);
  });
});

describe("a diff is held to rules before anyone sees it", () => {
  const base = ["--- a/f.ts", "+++ b/f.ts", "@@ -1,2 +1,2 @@", " keep", "-old", "+new"].join("\n");
  it("accepts a small, well-formed diff for the named file", () => { expect(validateDiff(base, "f.ts")).toBe(true); });
  it.each([
    ["another file", base.replace("a/f.ts", "a/g.ts").replace("b/f.ts", "b/g.ts"), "f.ts"],
    ["a different header", base.replace("+++ b/f.ts", "+++ b/other.ts"), "f.ts"],
    ["no hunk header", ["--- a/f.ts", "+++ b/f.ts", "-old", "+new"].join("\n"), "f.ts"],
    ["two hunks", `${base}\n@@ -9,1 +9,1 @@\n-x\n+y`, "f.ts"],
    ["a body line with no marker", `${base}\nnot a diff line`, "f.ts"],
    ["nothing added", ["--- a/f.ts", "+++ b/f.ts", "@@ -1,1 +0,0 @@", "-old"].join("\n"), "f.ts"],
    ["an added link", `${base}\n+see https://evil.example.net/x`, "f.ts"],
    ["an added secret", `${base}\n+const k = "${"AKIA" + "IOSFODNN7EXAMPLE"}";`, "f.ts"],
    ["an added require", `${base}\n+const x = require("child_process");`, "f.ts"],
    ["an added import", `${base}\n+import cp from "node:child_process";`, "f.ts"],
    ["an added eval", `${base}\n+eval(input);`, "f.ts"],
    ["too many added lines", `${base}\n${Array.from({ length: 11 }, (_, i) => `+l${i}`).join("\n")}`, "f.ts"],
  ])("refuses %s", (_n, diff, p) => { expect(validateDiff(diff, p)).toBe(false); });
});

describe("the rules of engagement the white-box agent runs under", () => {
  const roe = whiteboxRoe({ repo: "acme/shop", rangeId: "range_abc", now: 1_800_000_000_000, findings: 10 });
  it("are valid, range-only, white-box-only, one technique, and need no approval", () => {
    const p = parseRoe(roe);
    expect(p.ok).toBe(true);
    expect(roe.targets).toEqual([{ kind: "range", rangeId: "range_abc" }]);
    expect(roe.agents).toEqual(["whitebox"]);
    expect(roe.allowedTechniques).toEqual([WHITEBOX_TECHNIQUE]);
    expect("approval" in roe).toBe(false);
  });
  it("size the step budget to the work, and cap it", () => {
    expect(whiteboxRoe({ repo: "a/b", rangeId: "r", now: 1, findings: 0 }).budgets.steps).toBe(2);
    expect(roe.budgets.steps).toBe(62);
    expect(whiteboxRoe({ repo: "a/b", rangeId: "r", now: 1, findings: 10_000 }).budgets.steps).toBe(500);
  });
  it("buy no model time or money", () => { expect(roe.budgets).toMatchObject({ tokens: 1000, costUsd: 1 }); });
  it("have an id that differs by time and repository, and a window around now", () => {
    expect(whiteboxRoe({ repo: "acme/shop", rangeId: "range_abc", now: 1_800_000_000_001, findings: 10 }).runId).not.toBe(roe.runId);
    expect(roe.window.notBefore).toBeLessThan(1_800_000_000_000);
    expect(roe.window.notAfter).toBeGreaterThan(1_800_000_000_000);
  });
  it("refuse a technique other than the one named, in the guard itself", () => {
    const d = scope({ id: "a1", agent: "whitebox", tool: "range_request", class: "exploit-range", technique: "T1566", target: { kind: "range", rangeId: "range_abc" } }, roe, 1_800_000_000_000);
    expect(d).toMatchObject({ ok: false, reason: "technique-not-allowed" });
    const ok = scope({ id: "a1", agent: "whitebox", tool: "range_request", class: "exploit-range", technique: "T1190", target: { kind: "range", rangeId: "range_abc" } }, roe, 1_800_000_000_000);
    expect(ok).toEqual({ ok: true });
  });
  it("refuse a real site, whatever the agent asks", () => {
    const d = scope({ id: "a2", agent: "whitebox", tool: "http_probe", class: "probe", technique: "T1190", target: { kind: "verified-domain", url: "https://shop.example.com/" } }, roe, 1_800_000_000_000);
    expect(d).toMatchObject({ ok: false, reason: "target-not-in-roe" });
  });
});
