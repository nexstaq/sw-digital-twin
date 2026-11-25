import { readFileSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildRange } from "./generate";
import { startRange } from "./runtime";
import { shopFindings, shopGraph, WF } from "./fixtures";
import { PAYLOAD_CLASSES } from "./types";

/**
 * The range has no way to reach the network because it has no code that could. These tests fail the build if that changes:
 * first by reading the running code for anything that does I/O, then by watching a full workout for any attempt to connect.
 */

const dir = path.join(process.cwd(), "src/lib/sim/range");
const code = (file: string) => readFileSync(path.join(dir, file), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "").replace(/\s\/\/ .*$/gm, "");
const imports = (src: string) => [...src.matchAll(/(?:^|\n)\s*import\s+(?:type\s+)?[^;]*?from\s+["']([^"']+)["']/g)].map((m) => m[1]);

/** the parts that RUN: they may import only these */
const RUNNING = {
  "runtime.ts": ["zod", "./types"],
  "health.ts": ["@/lib/health/signals", "./types"],
  "types.ts": ["@/lib/graph/types", "@/lib/security/types"],
  "sha256.ts": [],
  "generate.ts": ["./sha256", "./types", "@/lib/graph/types", "@/lib/security/map", "@/lib/security/types"],
} as const;

describe("the running code can only compute", () => {
  for (const [file, allowed] of Object.entries(RUNNING)) {
    it(`${file} imports only ${allowed.join(", ") || "nothing"}`, () => { expect(imports(code(file)).sort()).toEqual([...allowed].sort()); });
    it(`${file} has no network, file, process, clock or randomness`, () => {
      const src = code(file);
      for (const [name, re] of [
        ["fetch", /\bfetch\s*\(/], ["XMLHttpRequest", /\bXMLHttpRequest\b/], ["WebSocket", /\bWebSocket\b/], ["EventSource", /\bEventSource\b/], ["process", /\bprocess\b/],
        ["require", /\brequire\s*\(/], ["dynamic import", /\bimport\s*\(/], ["eval", /\beval\s*\(|new\s+Function\b/], ["globalThis", /\bglobalThis\b/],
        ["timers", /\b(setTimeout|setInterval|setImmediate|queueMicrotask)\b/], ["wall clock", /Date\.now\s*\(|new\s+Date\s*\(\s*\)|performance\.now/], ["Math.random", /Math\.random/],
        ["crypto randomness", /crypto\.(randomUUID|getRandomValues|randomBytes)/], ["Worker", /\bWorker\b/], ["node: modules", /["']node:/],
      ] as const) expect(re.test(src), `${file} uses ${name}`).toBe(false);
    });
  }
  it("the scan above really reads the code (it would catch a fetch)", () => {
    const sample = "export const x = () => fetch('http://169.254.169.254/');";
    expect(/\bfetch\s*\(/.test(sample)).toBe(true);
    expect(imports("import net from 'node:net';\nimport { a } from \"./a\";")).toEqual(["node:net", "./a"]);
  });
});

describe("a full workout never tries to connect", () => {
  afterEach(() => vi.restoreAllMocks());

  it("no fetch and no socket, even when the payload asks for server-side request forgery", () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(() => { throw new Error("egress attempted: fetch"); });
    const connectSpy = vi.spyOn(net.Socket.prototype, "connect").mockImplementation(() => { throw new Error("egress attempted: socket"); });
    const r = startRange(buildRange({ sha: "b".repeat(40), graph: shopGraph() }, shopFindings()));
    for (const c of PAYLOAD_CLASSES) for (const [method, p] of [["GET", "/api/orders"], ["POST", "/api/orders"], ["GET", "/api/orders/9"], ["POST", "/api/admin/reset"]] as const) {
      r.handle({ method, path: p, role: "admin", payload: { class: c } });
    }
    r.handle({ method: "GET", path: "/api/orders/9", role: "user", payload: { class: "ssrf" } });
    for (const trigger of ["push", "pull_request", "outsider-pr"] as const) r.runWorkflow(WF, { trigger });
    r.flow("ext:stripe");
    r.finish();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(connectSpy).not.toHaveBeenCalled();
  });

  it("the guard against egress would notice one (the spy is wired correctly)", () => {
    vi.spyOn(net.Socket.prototype, "connect").mockImplementation(() => { throw new Error("egress attempted: socket"); });
    expect(() => new net.Socket().connect(80, "127.0.0.1")).toThrow(/egress attempted/);
  });

  it("an exercised SSRF returns a marker and what it reached, not a response from anywhere", () => {
    const r = startRange(buildRange({ sha: "b".repeat(40), graph: shopGraph() }, shopFindings()));
    const res = r.handle({ method: "GET", path: "/api/orders/9", role: "user", payload: { class: "ssrf" } });
    expect(res.body).toBe("ok");
    expect(res.proof).toMatch(/^SIM-PROOF-/);
    expect(Object.keys(res).sort()).toEqual(["body", "crown", "ms", "proof", "reached", "status", "traceId"].filter((k) => k in res).sort());
  });
});
