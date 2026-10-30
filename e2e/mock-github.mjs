// A tiny stand-in for github.com + api.github.com, so the e2e suite needs no network and no real credentials.
//   acme/shop  public;  its default branch has a FAILING "test" job.
//   acme/vault private; visible only to the signed-in test user (token tok-alice), who can push.
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, cpSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PORT = Number(process.env.MOCK_PORT ?? 4010);
const here = path.dirname(fileURLToPath(import.meta.url));
const TOKEN = "tok-alice";

// one real git commit of the fixture, archived exactly like GitHub does (pax header carries the sha)
const work = mkdtempSync(path.join(tmpdir(), "mock-gh-"));
cpSync(path.join(here, "fixture"), work, { recursive: true });
// Secrets are assembled here, at run time, so no key-shaped string is ever committed to the real repo.
writeFileSync(path.join(work, "src/config.ts"), `// payments\nexport const awsKey = "${"AK" + "IA" + "IOSFODNN7" + "EXAMPLE"}";\n`);
const git = (...a) => execFileSync("git", ["-C", work, "-c", "user.email=t@t", "-c", "user.name=t", ...a], { encoding: "utf8", env: { ...process.env, GIT_COMMITTER_DATE: "2026-01-02T03:04:05Z", GIT_AUTHOR_DATE: "2026-01-02T03:04:05Z" } });
git("init", "-q", "-b", "main"); git("add", "-A"); git("commit", "-qm", "init");
const SHA = git("rev-parse", "HEAD").trim();
const tarball = execFileSync("git", ["-C", work, "archive", "--format=tar.gz", `--prefix=acme-${SHA.slice(0, 7)}/`, "HEAD"], { maxBuffer: 1 << 26 });

const REPOS = { "acme/shop": { private: false }, "acme/vault": { private: true } };
const authed = (req) => req.headers.authorization === `Bearer ${TOKEN}`;
const visible = (name, req) => REPOS[name] && (!REPOS[name].private || authed(req));
const json = (res, code, body) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(body)); };
const ago = (h) => new Date(Date.now() - h * 3_600_000).toISOString();

// 10 runs on main: the newest failed, so the pipeline must read as failing
const runs = Array.from({ length: 10 }, (_, i) => ({
  id: 1000 - i, path: ".github/workflows/ci.yml", name: "CI", head_branch: "main", head_sha: SHA, event: "push", status: "completed",
  conclusion: i === 0 ? "failure" : "success", run_attempt: 1, created_at: ago(1 + i * 3), updated_at: ago(1 + i * 3), html_url: `https://github.com/acme/shop/actions/runs/${1000 - i}`,
}));
const jobsFor = (id) => ({ jobs: [
  { name: "lint", status: "completed", conclusion: "success", html_url: `https://github.com/acme/shop/actions/runs/${id}/job/1`, steps: [{ name: "Run lint", conclusion: "success" }] },
  { name: "test", status: "completed", conclusion: id === 1000 ? "failure" : "success", html_url: `https://github.com/acme/shop/actions/runs/${id}/job/2`, steps: [{ name: "Run unit tests", conclusion: id === 1000 ? "failure" : "success" }] },
  { name: "deploy", status: "completed", conclusion: id === 1000 ? "skipped" : "success", html_url: `https://github.com/acme/shop/actions/runs/${id}/job/3`, steps: [] },
] });

// ---- OSV.dev stand-in: lodash 4.17.15 has two advisories, nothing else does
const ADVISORIES = {
  "GHSA-p6mc-m468-83gw": { id: "GHSA-p6mc-m468-83gw", aliases: ["CVE-2020-8203"], summary: "Prototype Pollution in lodash", severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H" }], database_specific: { cwe_ids: ["CWE-1321"], severity: "HIGH" }, affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.19" }] }] }], references: [{ type: "ADVISORY", url: "https://github.com/advisories/GHSA-p6mc-m468-83gw" }] },
  "GHSA-35jh-r3h4-6jhm": { id: "GHSA-35jh-r3h4-6jhm", aliases: ["CVE-2021-23337"], summary: "Command Injection in lodash", severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }], database_specific: { cwe_ids: ["CWE-77"], severity: "HIGH" }, affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ events: [{ fixed: "4.17.21" }] }] }], references: [] },
};

createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const p = url.pathname;
  let m;
  // ---- github.com (OAuth)
  if (p === "/login/oauth/authorize") {
    const to = new URL(url.searchParams.get("redirect_uri"));
    to.searchParams.set("code", "code-1"); to.searchParams.set("state", url.searchParams.get("state"));
    res.writeHead(302, { location: to.toString() }); return res.end();
  }
  if (p === "/login/oauth/access_token") return json(res, 200, { access_token: TOKEN, refresh_token: "r-1", expires_in: 28800 });
  // ---- api.github.com
  if (p === "/user") return authed(req) ? json(res, 200, { id: 1, login: "alice", avatar_url: null }) : json(res, 401, {});
  if (p === "/user/installations") return authed(req) ? json(res, 200, { installations: [{ id: 1, account: { login: "acme", avatar_url: null } }] }) : json(res, 401, {});
  if (p === "/user/installations/1/repositories") {
    return json(res, 200, { repositories: Object.entries(REPOS).map(([full_name, r]) => ({ full_name, private: r.private, description: "Fixture repo", language: "TypeScript", pushed_at: ago(2), permissions: { push: true } })) });
  }
  if ((m = /^\/repos\/(acme\/[\w-]+)$/.exec(p))) {
    if (!visible(m[1], req)) return json(res, 404, { message: "Not Found" });
    return json(res, 200, { default_branch: "main", private: REPOS[m[1]].private, permissions: authed(req) ? { pull: true, push: true } : undefined });
  }
  if ((m = /^\/repos\/(acme\/[\w-]+)\/tarball(\/.*)?$/.exec(p))) {
    if (!visible(m[1], req)) return json(res, 404, { message: "Not Found" });
    res.writeHead(200, { "content-type": "application/x-gzip" }); return res.end(tarball);
  }
  if ((m = /^\/repos\/(acme\/[\w-]+)\/actions\/runs$/.exec(p))) return visible(m[1], req) ? json(res, 200, { workflow_runs: m[1] === "acme/shop" ? runs : [] }) : json(res, 404, {});
  if ((m = /^\/repos\/acme\/[\w-]+\/actions\/runs\/(\d+)\/jobs$/.exec(p))) return json(res, 200, jobsFor(Number(m[1])));
  if (/^\/repos\/acme\/[\w-]+\/deployments$/.test(p)) return json(res, 200, []);
  if (/^\/repos\/acme\/[\w-]+\/commits\/[0-9a-f]+$/.test(p)) return json(res, 200, { commit: { committer: { date: "2026-01-02T03:04:05Z" } } });
  if (p === "/v1/querybatch" && req.method === "POST") {
    let body = ""; req.on("data", (c) => (body += c));
    req.on("end", () => json(res, 200, { results: JSON.parse(body).queries.map((q) => ({ vulns: q.package.name === "lodash" && q.version === "4.17.15" ? Object.keys(ADVISORIES).map((id) => ({ id })) : [] })) }));
    return;
  }
  if ((m = /^\/v1\/vulns\/([\w-]+)$/.exec(p))) return ADVISORIES[m[1]] ? json(res, 200, ADVISORIES[m[1]]) : json(res, 404, {});
  // file contents at the scanned commit (private repos only for the signed-in user), raw like GitHub's raw media type
  if ((m = /^\/repos\/(acme\/[\w-]+)\/contents\/(.+)$/.exec(p))) {
    if (!visible(m[1], req)) return json(res, 404, { message: "Not Found" });
    const file = path.join(work, decodeURIComponent(m[2]));
    if (!file.startsWith(work + path.sep) || !existsSync(file)) return json(res, 404, { message: "Not Found" });
    res.writeHead(200, { "content-type": "text/plain" }); return res.end(readFileSync(file));
  }
  if (p === "/__health") return json(res, 200, { ok: true, sha: SHA });
  json(res, 404, { message: `mock has no ${p}` });
}).listen(PORT, () => console.log(`mock github on ${PORT}, fixture commit ${SHA.slice(0, 7)}`));
