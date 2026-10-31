import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { ciWorkflow, NUCLEI_IMAGE } from "./ci";
import { analyzePipelines, scanWorkflow } from "./analyzers/pipeline";

const YAML = ciWorkflow({ origin: "https://app.example.com" });
const wf = parse(YAML) as { on: Record<string, unknown>; permissions: Record<string, string>; jobs: { nuclei: { env: Record<string, string>; steps: { name: string; run: string }[]; "timeout-minutes": number } } };

describe("ciWorkflow", () => {
  it("is valid YAML with the shape GitHub Actions needs", () => {
    expect(wf.jobs.nuclei.steps).toHaveLength(3);
    expect(wf.jobs.nuclei["timeout-minutes"]).toBe(30);
    expect(wf.permissions).toEqual({ contents: "read", "id-token": "write" }); // least privilege: read code, and prove identity
  });
  it("never runs on pull requests, so a stranger's PR cannot start a scan or get an identity token", () => {
    expect(Object.keys(wf.on).sort()).toEqual(["schedule", "workflow_dispatch"]);
    expect(YAML).not.toMatch(/pull_request/);
  });
  it("will not run until a target is named and ownership is confirmed", () => {
    const guard = wf.jobs.nuclei.steps[0].run;
    expect(guard).toContain("SECURITY_TEST_TARGET");
    expect(guard).toMatch(/https:\/\/\*\)/); // https targets only
    expect(guard).toContain('"$CONFIRMED" != "yes"');
    expect(guard).toContain("exit 1");
    expect(YAML).toMatch(/unauthorised testing can be illegal/i);
  });
  it("is gentle by default: rate limited, no intrusive or denial-of-service templates, no third-party callbacks", () => {
    const run = wf.jobs.nuclei.steps[1].run;
    expect(run).toContain("-etags dos,intrusive,fuzz,bruteforce");
    expect(run).toMatch(/-rate-limit 20/);
    expect(run).toContain(" -ni "); // no out-of-band callbacks to a third-party server
  });
  it("pins the scanner image by digest", () => {
    expect(NUCLEI_IMAGE).toMatch(/^projectdiscovery\/nuclei:v\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$/);
    expect(wf.jobs.nuclei.steps[1].run).toContain(NUCLEI_IMAGE);
    expect(YAML).not.toMatch(/nuclei:latest/);
  });
  it("authenticates with GitHub's OIDC token for THIS service only, and stores no secret", () => {
    const send = wf.jobs.nuclei.steps[2].run;
    expect(send).toContain("ACTIONS_ID_TOKEN_REQUEST_URL");
    expect(send).toContain("audience=$MC_ORIGIN");
    expect(send).toContain("::add-mask::$TOKEN"); // the token never prints
    expect(send).toContain("/api/security/import?repo=$GITHUB_REPOSITORY");
    expect(wf.jobs.nuclei.env.MC_ORIGIN).toBe("https://app.example.com");
    expect(YAML).not.toMatch(/secrets\./);
  });
  it("an empty result is sent too, so findings that were fixed disappear", () => {
    expect(wf.jobs.nuclei.steps[1].run).toContain('"results":[]');
  });
  it("refuses anything but an https origin, so it cannot be used to aim the upload elsewhere", () => {
    for (const bad of ["http://app.example.com", "https://app.example.com/path", "https://a.com; curl evil", "javascript:x", ""]) expect(() => ciWorkflow({ origin: bad }), bad).toThrow();
    expect(() => ciWorkflow({ origin: "https://localhost:3000" })).not.toThrow();
    expect(() => ciWorkflow({ origin: "http://localhost:3000" })).not.toThrow(); // local development only
    expect(() => ciWorkflow({ origin: "http://localhost.evil.com" })).toThrow();
  });

  it("DOGFOOD: our own pipeline scanner finds nothing wrong with the workflow we hand out", async () => {
    expect(scanWorkflow(YAML)).toEqual([]);
    expect(await analyzePipelines({ repo: "a/b", files: [".github/workflows/security.yml"], read: async () => YAML })).toEqual([]);
  });
});
