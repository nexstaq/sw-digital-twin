import type { Finding, Severity, SecurityContext } from "../types";
import { fingerprint } from "../util";

/** `Dockerfile`, `Dockerfile.dev`, `api.dockerfile`: but not a source file that merely starts with the word (`Dockerfile.ts`). */
const DOCKERFILE = /(^|\/)(Dockerfile(\.(?!(?:ts|tsx|js|jsx|mjs|md|json|py|go|rs|txt|ya?ml|sh)$)[\w-]+)?|[^/]+\.dockerfile)$/i;
const COMPOSE = /(^|\/)(docker-)?compose[^/]*\.ya?ml$/i;
const SECRETISH = /(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)/i;

interface Hit { ruleId: string; severity: Severity; title: string; line: number; reason: string; fix: string; cwe: string[]; owasp?: string; key: string; confidence?: "high" | "medium" | "low" }

/** Joins `\` continuations so a RUN spread over lines is one instruction, remembering the first physical line. */
function instructions(text: string): { line: number; text: string }[] {
  const out: { line: number; text: string }[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    let t = lines[i];
    const start = i + 1;
    while (/\\\s*$/.test(t) && i + 1 < lines.length) t = t.replace(/\\\s*$/, " ") + lines[++i].trim();
    if (t.trim() && !t.trim().startsWith("#")) out.push({ line: start, text: t.trim() });
  }
  return out;
}

export function scanDockerfile(text: string): Hit[] {
  const ins = instructions(text);
  const hits: Hit[] = [];
  const froms = ins.filter((i) => /^FROM\s/i.test(i.text));
  const last = froms.at(-1);

  // the image that ships is the last stage: does it ever drop root?
  if (last) {
    const afterLast = ins.filter((i) => i.line > last.line);
    const users = afterLast.filter((i) => /^USER\s/i.test(i.text));
    const finalUser = users.at(-1)?.text.split(/\s+/)[1] ?? "";
    if (!users.length || /^(root|0)(:|$)/.test(finalUser)) {
      hits.push({ ruleId: "DOCKER/runs-as-root", severity: "medium", title: "Container runs as root", line: last.line, key: "root",
        reason: "With no non-root `USER`, the application runs as root inside the container. A bug that lets an attacker run code then gives them root there, which makes a container escape or a mounted-volume attack far easier.",
        fix: "Create an unprivileged user and switch to it before the final CMD, for example `RUN adduser -D app` then `USER app`.", cwe: ["CWE-250"], owasp: "A05:2021 Security Misconfiguration" });
    }
  }

  for (const f of froms) {
    const m = /^FROM\s+(?:--\S+\s+)?(\S+)/i.exec(f.text);
    const img = m?.[1] ?? "";
    if (!img || img === "scratch" || /^\$|^[a-z0-9_-]+$/i.test(img) && froms.some((x) => new RegExp(`\\bAS\\s+${img}\\b`, "i").test(x.text))) continue; // build-stage reference
    if (/@sha256:/.test(img)) continue;
    const tag = img.includes(":") ? img.split(":").pop()! : "";
    if (!tag || tag === "latest") {
      hits.push({ ruleId: "DOCKER/unpinned-base", severity: "low", title: `Base image ${img} is not pinned`, line: f.line, key: `base:${img}`,
        reason: `\`${img}\` has no version tag (or uses \`latest\`), so each build can silently pull a different, possibly vulnerable or malicious, base image.`,
        fix: "Pin a specific version, ideally with its digest: `FROM node:24.1-alpine@sha256:…`.", cwe: ["CWE-1104"], owasp: "A06:2021 Vulnerable and Outdated Components" });
    }
  }

  for (const i of ins) {
    const m = /^(ENV|ARG)\s+([A-Za-z0-9_]+)(?:\s*=\s*|\s+)(\S.*)$/i.exec(i.text);
    if (m && SECRETISH.test(m[2]) && m[3].replace(/["']/g, "").length >= 4 && !/^\$\{?[A-Za-z_]/.test(m[3])) {
      hits.push({ ruleId: "DOCKER/secret-in-image", severity: "high", title: `${m[2]} is baked into the image`, line: i.line, key: `secret:${m[2]}`,
        reason: `A value for ${m[2]} is written into the image. Anyone who can pull the image (or read its layers with \`docker history\`) can read it, even if you later unset it.`,
        fix: "Do not put secrets in `ENV` or `ARG`. Pass them at runtime (an environment variable, a mounted secret, or your orchestrator's secret store) or use BuildKit `--mount=type=secret` during the build.", cwe: ["CWE-798", "CWE-540"], owasp: "A02:2021 Cryptographic Failures" });
    }
    if (/^RUN\b.*\b(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b/i.test(i.text)) {
      hits.push({ ruleId: "DOCKER/curl-pipe-shell", severity: "medium", title: "Image build downloads a script and runs it unverified", line: i.line, key: `curlsh:${i.text}`,
        reason: "Whatever that URL serves at build time gets executed as part of your image. A compromised host means a compromised image.",
        fix: "Download to a file, verify a pinned checksum, then run it, or install from a package manager at a pinned version.", cwe: ["CWE-494"], owasp: "A08:2021 Software and Data Integrity Failures" });
    }
    if (/^ADD\s+https?:\/\//i.test(i.text)) {
      hits.push({ ruleId: "DOCKER/add-remote", severity: "low", title: "ADD fetches a remote URL", line: i.line, key: `add:${i.text}`,
        reason: "`ADD <url>` downloads a file with no integrity check, and the content can change between builds.", fix: "Use `curl` with a pinned checksum in a `RUN`, or copy a vendored file with `COPY`.", cwe: ["CWE-494"] });
    }
    if (/^RUN\b.*\bchmod\s+(?:-R\s+)?0?777\b/i.test(i.text)) {
      hits.push({ ruleId: "DOCKER/chmod-777", severity: "low", title: "Files made world-writable", line: i.line, key: `chmod:${i.text}`,
        reason: "`chmod 777` lets any user in the container modify those files, which turns a small compromise into persistence.", fix: "Grant only what the app user needs, for example `chown app:app` and `chmod 755`.", cwe: ["CWE-732"], owasp: "A05:2021 Security Misconfiguration" });
    }
    if (/^EXPOSE\b.*\b22\b/i.test(i.text)) {
      hits.push({ ruleId: "DOCKER/expose-ssh", severity: "medium", title: "SSH port exposed", line: i.line, key: "ssh", confidence: "medium",
        reason: "An SSH daemon inside a container is rarely needed and adds an attack surface and credentials to manage.", fix: "Remove it. Use `docker exec` or your platform's shell access instead.", cwe: ["CWE-1327"] });
    }
  }
  return hits;
}

export function scanCompose(text: string): Hit[] {
  const lines = text.split("\n");
  const hits: Hit[] = [];
  const add = (ruleId: string, severity: Severity, title: string, line: number, reason: string, fix: string, cwe: string[], key: string) => hits.push({ ruleId, severity, title, line, reason, fix, cwe, key, owasp: "A05:2021 Security Misconfiguration" });
  lines.forEach((l, i) => {
    if (/^\s*privileged:\s*true\b/.test(l)) add("COMPOSE/privileged", "high", "Container runs privileged", i + 1, "A privileged container has nearly the host's full power. Code that breaks out of the app owns the machine.", "Remove `privileged: true`; grant only the specific capability you need with `cap_add`.", ["CWE-250"], "privileged");
    if (/^\s*network_mode:\s*["']?host\b/.test(l)) add("COMPOSE/host-network", "medium", "Container shares the host network", i + 1, "On the host network the container can reach, and be reached on, every host interface, bypassing Docker's isolation.", "Use a bridge network and publish only the ports you need.", ["CWE-668"], "hostnet");
    if (/^\s*pid:\s*["']?host\b/.test(l)) add("COMPOSE/host-pid", "high", "Container shares the host process namespace", i + 1, "It can see and signal every process on the host.", "Remove `pid: host`.", ["CWE-250"], "hostpid");
    if (/\/var\/run\/docker\.sock/.test(l)) add("COMPOSE/docker-socket", "high", "Docker socket mounted into a container", i + 1, "Access to the Docker socket is equivalent to root on the host: the container can start any container with any mount.", "Remove the mount, or use a socket proxy that allows only the calls you need.", ["CWE-250"], "sock");
  });
  return hits;
}

export async function analyzeContainers(ctx: SecurityContext): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const path of ctx.files) {
    const isDocker = DOCKERFILE.test(path), isCompose = COMPOSE.test(path);
    if (!isDocker && !isCompose) continue;
    const text = await ctx.read(path);
    if (!text) continue;
    for (const h of isDocker ? scanDockerfile(text) : scanCompose(text)) {
      out.push({ id: fingerprint("container", path, h.ruleId, h.key), ruleId: h.ruleId, category: "container", severity: h.severity, title: h.title, path, line: h.line, reason: h.reason, fix: h.fix, cwe: h.cwe, owasp: h.owasp, confidence: h.confidence ?? "high", detail: {} });
    }
  }
  return out;
}
