import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { ciWorkflow, NUCLEI_IMAGE, simulationWorkflow } from "./ci";
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

const SIM_YAML = simulationWorkflow({ origin: "https://app.example.com" });
const sim = parse(SIM_YAML) as { on: Record<string, unknown>; permissions: Record<string, string>; jobs: { simulate: { env: Record<string, string>; steps: { name?: string; run?: string; uses?: string }[]; "timeout-minutes": number } } };

describe("simulationWorkflow", () => {
  it("is valid YAML, least-privilege, and never runs on a pull request", () => {
    expect(sim.jobs.simulate.steps).toHaveLength(5); // confirm target, ask plan, probe, report, print a redacted transcript to the log
    expect(sim.permissions).toEqual({ contents: "read", "id-token": "write" });
    expect(Object.keys(sim.on).sort()).toEqual(["schedule", "workflow_dispatch"]);
    expect(SIM_YAML).not.toMatch(/pull_request/);
  });
  it("runs at a different time than the live security test, so the two never collide", () => {
    expect((sim.on as { schedule: { cron: string }[] }).schedule[0].cron).not.toBe((wf.on as { schedule: { cron: string }[] }).schedule[0].cron);
  });
  it("will not run until a target is named and ownership is confirmed, same gate as the live security test", () => {
    const guard = sim.jobs.simulate.steps[0].run!;
    expect(guard).toContain("SECURITY_TEST_TARGET");
    expect(guard).toMatch(/https:\/\/\*\)/);
    expect(guard).toContain('"$CONFIRMED" != "yes"');
    expect(SIM_YAML).toMatch(/unauthorised testing can be illegal/i);
  });
  it("asks Mission Control which requests it may make before it makes any; it never sends a request to the site itself from here", () => {
    const ask = sim.jobs.simulate.steps[1].run!;
    expect(ask).toContain("/api/security/simulate/ci-plan?repo=$GITHUB_REPOSITORY");
    expect(ask).toContain("::add-mask::$TOKEN");
    expect(ask).toContain('\\"profile\\":\\"$PROFILE\\"');
    expect(ask).toContain('\\"confirmed\\":true');
  });
  it("probes gently: GET only (curl with no -X on the probe), a pause between requests, a 4 KB cap, a short timeout", () => {
    const probe = sim.jobs.simulate.steps[2].run!;
    expect(probe).toContain("sleep 0.3");
    expect(probe).toContain("-r 0-4095");
    expect(probe).toContain("--max-time 10");
    expect(probe).not.toMatch(/-X\s*(POST|PUT|DELETE|PATCH)/);
  });
  it("reports back, authenticated the same OIDC way, and stores no secret", () => {
    const send = sim.jobs.simulate.steps[3].run!;
    expect(send).toContain("/api/security/simulate/ci-report?repo=$GITHUB_REPOSITORY");
    expect(send).toContain("::add-mask::$TOKEN");
    expect(SIM_YAML).not.toMatch(/secrets\./);
  });
  it("prints a redacted transcript to the run's own log, with the one-time plan token stripped out", () => {
    const redact = sim.jobs.simulate.steps[4].run!;
    expect(redact).toContain("del(.token)");
  });
  it("needs no container image and no third-party action at all: the whole thing is curl and jq", () => {
    expect(SIM_YAML).not.toMatch(/docker run/);
    expect(SIM_YAML).not.toMatch(/uses:/);
  });
  it("defaults the profile to \"access\" when the repository variable is not set", () => {
    expect(sim.jobs.simulate.env.PROFILE).toBe("${{ vars.SECURITY_TEST_PROFILE || 'access' }}");
  });
  it("refuses anything but an https origin", () => {
    for (const bad of ["http://app.example.com", "https://app.example.com/path", "javascript:x", ""]) expect(() => simulationWorkflow({ origin: bad }), bad).toThrow();
    expect(() => simulationWorkflow({ origin: "https://localhost:3000" })).not.toThrow();
  });

  it("DOGFOOD: our own pipeline scanner finds nothing wrong with the workflow we hand out", async () => {
    expect(scanWorkflow(SIM_YAML)).toEqual([]);
    expect(await analyzePipelines({ repo: "a/b", files: [".github/workflows/simulate.yml"], read: async () => SIM_YAML })).toEqual([]);
  });
});
