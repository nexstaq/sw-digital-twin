import { describe, expect, it } from "vitest";
import { analyzePipelines, scanWorkflow } from "./pipeline";

const rules = (y: string) => scanWorkflow(y).map((h) => h.ruleId).sort();
const find = (y: string, id: string) => scanWorkflow(y).find((h) => h.ruleId === id);

const PWN = `name: PR
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: npm test
`;

describe("scanWorkflow", () => {
  it("flags the pwn-request pattern as critical, on the exact line of the dangerous checkout", () => {
    const h = find(PWN, "GHA/pwn-request")!;
    expect(h).toMatchObject({ severity: "critical", line: 9 });
    expect(h.cwe).toContain("CWE-94");
  });

  it("pull_request_target alone is only a low note, not an alarm", () => {
    const y = `on: pull_request_target\npermissions: { contents: read }\njobs:\n  a:\n    steps:\n      - run: echo hi\n`;
    expect(find(y, "GHA/pull-request-target")).toMatchObject({ severity: "low" });
    expect(find(y, "GHA/pwn-request")).toBeUndefined();
  });

  it("finds script injection in run blocks (inline and multi-line), and not when passed via env", () => {
    const bad = `on: issues\npermissions: read-all\njobs:\n  a:\n    steps:\n      - run: echo "\${{ github.event.issue.title }}"\n      - run: |\n          echo start\n          echo "\${{ github.head_ref }}"\n`;
    const hits = scanWorkflow(bad).filter((h) => h.ruleId === "GHA/script-injection");
    expect(hits.map((h) => h.line)).toEqual([6, 9]);
    const safe = `on: issues\npermissions: read-all\njobs:\n  a:\n    steps:\n      - env:\n          TITLE: \${{ github.event.issue.title }}\n        run: echo "$TITLE"\n`;
    expect(find(safe, "GHA/script-injection")).toBeUndefined();
  });

  it("does not treat harmless expressions as injection", () => {
    const y = `on: push\npermissions: read-all\njobs:\n  a:\n    steps:\n      - run: echo "\${{ github.sha }} \${{ runner.os }}"\n`;
    expect(find(y, "GHA/script-injection")).toBeUndefined();
  });

  it("unpinned actions: third-party medium, GitHub-owned low, SHA-pinned and local ones are fine", () => {
    const y = `on: push\npermissions: read-all\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: some-org/deploy@main\n      - uses: other/thing@${"a".repeat(40)}\n      - uses: ./local-action\n      - uses: docker://alpine:3\n`;
    const un = scanWorkflow(y).filter((h) => h.ruleId === "GHA/unpinned-action");
    expect(un.map((h) => [h.severity, h.line])).toEqual([["low", 6], ["medium", 7]]);
  });

  it("token permissions: write-all is medium; a missing block is a low note; a block silences it", () => {
    expect(find(`on: push\npermissions: write-all\njobs: {}\n`, "GHA/write-all")).toMatchObject({ severity: "medium", line: 2 });
    expect(find(`on: push\njobs:\n  a:\n    steps: []\n`, "GHA/no-permissions")).toMatchObject({ severity: "low", line: 2 });
    expect(find(`on: push\npermissions:\n  contents: read\njobs: {}\n`, "GHA/no-permissions")).toBeUndefined();
    expect(find(`on: push\njobs:\n  a:\n    permissions: { contents: read }\n    steps: []\n`, "GHA/no-permissions")).toBeUndefined();
  });

  it("flags curl | sh", () => {
    expect(find(`on: push\npermissions: read-all\njobs:\n  a:\n    steps:\n      - run: curl -fsSL https://x.sh | sudo bash\n`, "GHA/curl-pipe-shell")).toMatchObject({ severity: "medium", line: 6 });
  });

  it("a clean workflow produces nothing", () => {
    const y = `on: push\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@${"b".repeat(40)}\n      - run: npm test\n`;
    expect(rules(y)).toEqual([]);
  });
});

describe("analyzePipelines", () => {
  it("only reads workflow files, pins path and line, and merges the same issue repeated on several lines", async () => {
    const y = `on: push\npermissions: read-all\njobs:\n  a:\n    steps:\n      - uses: foo/bar@v1\n      - uses: foo/bar@v1\n`;
    const out = await analyzePipelines({ repo: "a/b", files: [".github/workflows/ci.yml", "src/x.yml"], read: async (p) => (p.endsWith("ci.yml") ? y : "uses: evil/x@v1") });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ category: "pipeline", path: ".github/workflows/ci.yml", line: 6, severity: "medium" });
    expect(out[0].detail.lines).toEqual([6, 7]);
  });
  it("ids stay the same when lines shift, so a finding is not reported as new after an unrelated edit", async () => {
    const a = `on: push\npermissions: read-all\njobs:\n  a:\n    steps:\n      - uses: foo/bar@v1\n`;
    const b = `# a comment\n# another\n${a}`;
    const get = (y: string) => analyzePipelines({ repo: "a/b", files: [".github/workflows/ci.yml"], read: async () => y });
    expect((await get(a))[0].id).toBe((await get(b))[0].id);
    expect((await get(b))[0].line).toBe(8);
  });
});
