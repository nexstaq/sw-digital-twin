import { describe, expect, it } from "vitest";
import { analyzeContainers, scanCompose, scanDockerfile } from "./container";

const ids = (t: string) => scanDockerfile(t).map((h) => h.ruleId).sort();
const SECRET_VAL = "hunter" + "2hunter2";

describe("scanDockerfile", () => {
  it("flags a root container on the final FROM line", () => {
    const h = scanDockerfile(`FROM node:24-alpine\nCOPY . .\nCMD ["node","x.js"]\n`).find((x) => x.ruleId === "DOCKER/runs-as-root")!;
    expect(h).toMatchObject({ severity: "medium", line: 1 });
  });
  it("accepts a non-root USER, and still flags an explicit root", () => {
    expect(ids(`FROM node:24-alpine\nUSER app\nCMD x\n`)).toEqual([]);
    expect(ids(`FROM node:24-alpine\nUSER root\nCMD x\n`)).toContain("DOCKER/runs-as-root");
    expect(ids(`FROM node:24-alpine\nUSER 1000:1000\n`)).toEqual([]);
  });
  it("judges only the shipped (last) stage: root in a build stage is fine", () => {
    const t = `FROM node:24 AS build\nRUN npm ci\nFROM node:24-alpine\nUSER app\nCOPY --from=build /a /a\n`;
    expect(ids(t)).toEqual([]);
  });
  it("unpinned base images: no tag and latest are flagged; tags, digests, scratch and stage names are not", () => {
    expect(ids(`FROM ubuntu\nUSER a\n`)).toEqual(["DOCKER/unpinned-base"]);
    expect(ids(`FROM node:latest\nUSER a\n`)).toEqual(["DOCKER/unpinned-base"]);
    expect(ids(`FROM node:24\nUSER a\n`)).toEqual([]);
    expect(ids(`FROM node@sha256:${"a".repeat(64)}\nUSER a\n`)).toEqual([]);
    expect(ids(`FROM golang:1.22 AS b\nFROM scratch\nCOPY --from=b /x /x\nUSER 1\n`)).toEqual([]);
    expect(ids(`FROM golang:1.22 AS b\nFROM b\nUSER 1\n`)).toEqual([]);
  });
  it("secrets in ENV/ARG are high; empty values and variable references are not", () => {
    const hits = scanDockerfile(`FROM a:1\nUSER u\nENV DB_PASSWORD=${SECRET_VAL}\nARG API_KEY ${SECRET_VAL}\nENV TOKEN=\nENV PASSWORD=\${FROM_BUILD}\nENV NODE_ENV=production\n`).filter((h) => h.ruleId === "DOCKER/secret-in-image");
    expect(hits.map((h) => h.line)).toEqual([3, 4]);
    expect(JSON.stringify(hits)).not.toContain(SECRET_VAL);
  });
  it("catches curl|sh across a line continuation, ADD url, chmod 777 and EXPOSE 22", () => {
    const t = `FROM a:1\nUSER u\nRUN curl -fsSL https://x.sh \\\n  | sh\nADD https://x/y.tgz /y\nRUN chmod -R 777 /app\nEXPOSE 80 22\n`;
    expect(ids(t)).toEqual(["DOCKER/add-remote", "DOCKER/chmod-777", "DOCKER/curl-pipe-shell", "DOCKER/expose-ssh"]);
    expect(scanDockerfile(t).find((h) => h.ruleId === "DOCKER/curl-pipe-shell")!.line).toBe(3); // first physical line
  });
});

describe("scanCompose", () => {
  it("flags privileged, host network, host pid and the docker socket with lines", () => {
    const y = `services:\n  a:\n    privileged: true\n    network_mode: host\n    pid: host\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n`;
    expect(scanCompose(y).map((h) => [h.ruleId, h.line])).toEqual([["COMPOSE/privileged", 3], ["COMPOSE/host-network", 4], ["COMPOSE/host-pid", 5], ["COMPOSE/docker-socket", 7]]);
  });
  it("a normal compose file is clean", () => { expect(scanCompose(`services:\n  a:\n    image: x:1\n    ports: ["80:80"]\n`)).toEqual([]); });
});

describe("analyzeContainers", () => {
  it("picks Dockerfiles and compose files by name, with stable ids", async () => {
    const files: Record<string, string> = { Dockerfile: "FROM node:24\n", "deploy/api.dockerfile": "FROM node:24\n", "docker-compose.yml": "privileged: true\n", "src/Dockerfile.ts": "FROM x\n", "README.md": "FROM x" };
    const out = await analyzeContainers({ repo: "a/b", files: Object.keys(files), read: async (p) => files[p] ?? null });
    expect(out.map((f) => f.path).sort()).toEqual(["Dockerfile", "deploy/api.dockerfile", "docker-compose.yml"]);
    expect(new Set(out.map((f) => f.id)).size).toBe(out.length);
  });
});
