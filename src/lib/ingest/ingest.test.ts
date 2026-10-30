import { gitAuthEnv } from "./repo";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { validateGraph } from "@/lib/graph/integrity";
import type { TwinGraph } from "@/lib/graph/types";
import { parseCodeowners } from "./builder";
import { analyzeDirectory } from "./pipeline";
import { MAX_FILE_BYTES, listFiles, makeReader, parseRepo } from "./repo";
import { globToRegExp } from "./util";

async function scan(dir: string): Promise<{ graph: TwinGraph; warnings: string[]; events: string[] }> {
  const events: string[] = [];
  for await (const e of analyzeDirectory(dir, "test/repo", Date.now(), undefined, { narrate: async (g) => ({ graph: g, source: "rules" }) })) {
    events.push(e.type);
    if (e.type === "done") return { graph: e.graph, warnings: e.warnings, events };
    if (e.type === "error") throw new Error(e.message);
  }
  throw new Error("no done event");
}
const put = async (root: string, rel: string, body: string) => {
  await mkdir(path.dirname(path.join(root, rel)), { recursive: true });
  await writeFile(path.join(root, rel), body);
};
const byLabel = (g: TwinGraph, label: string | RegExp) => g.nodes.find((n) => (typeof label === "string" ? n.label === label : label.test(n.label)));

describe("parseRepo (the shell-out boundary)", () => {
  it("accepts owner/repo and github urls", () => {
    expect(parseRepo("vercel/next.js").url).toBe("https://github.com/vercel/next.js.git");
    expect(parseRepo("https://github.com/vercel/next.js.git/").name).toBe("next.js");
  });
  it.each([
    "https://evil.com/a/b", "file:///etc/passwd", "--upload-pack=touch /tmp/x", "a/b; rm -rf /", "http://github.com/a/b",
    "ssh://git@github.com/a/b", "https://github.com/a/b/c", "../../etc", "",
  ])("rejects %s", (bad) => expect(() => parseRepo(bad)).toThrow());
  it("rejects hostile refs", () => {
    expect(() => parseRepo("a/b", "--evil")).toThrow();
    expect(() => parseRepo("a/b", "x/../y")).toThrow();
    expect(parseRepo("a/b", "release/1.2").ref).toBe("release/1.2");
  });
});

describe("file access safety", () => {
  let root: string;
  beforeAll(async () => {
    root = await mkdtemp(path.join(tmpdir(), "twin-test-"));
    await put(root, "ok.txt", "hi");
    await put(root, "node_modules/x/index.js", "skip me");
    await put(root, "big.txt", "x".repeat(MAX_FILE_BYTES + 1));
    const { symlink } = await import("node:fs/promises");
    await symlink("/etc/passwd", path.join(root, "link")).catch(() => {});
  });
  afterAll(() => rm(root, { recursive: true, force: true }));
  it("skips node_modules and symlinks", async () => {
    const files = await listFiles(root);
    expect(files).toContain("ok.txt");
    expect(files.some((f) => f.includes("node_modules"))).toBe(false);
    expect(files).not.toContain("link");
  });
  it("refuses paths that escape the checkout and oversized files", async () => {
    const read = makeReader(root);
    expect(await read("../../etc/passwd")).toBeNull();
    expect(await read("big.txt")).toBeNull();
    expect(await read("ok.txt")).toBe("hi");
  });
});

describe("CODEOWNERS", () => {
  it("last matching rule wins", () => {
    const rules = parseCodeowners("* @all\n/apps/web/ @web\n*.tf @infra # comment\n");
    const owner = (p: string) => rules.filter((r) => r.re.test(p)).at(-1)?.owners;
    expect(owner("README.md")).toEqual(["@all"]);
    expect(owner("apps/web/page.tsx")).toEqual(["@web"]);
    expect(owner("infra/main.tf")).toEqual(["@infra"]);
  });
  it("globs", () => {
    expect(globToRegExp("/docs/").test("docs/a/b.md")).toBe(true);
    expect(globToRegExp("/docs/").test("x/docs/a.md")).toBe(false);
  });
});

describe("Next.js + Actions + compose + Terraform repo", () => {
  let root: string;
  let res: Awaited<ReturnType<typeof scan>>;
  beforeAll(async () => {
    root = await mkdtemp(path.join(tmpdir(), "twin-next-"));
    await put(root, "package.json", JSON.stringify({ name: "shop", scripts: { start: "next start" }, dependencies: { next: "15", react: "19", stripe: "1", pg: "8", "@sendgrid/mail": "1" } }));
    await put(root, "src/app/api/orders/route.ts", "export async function GET() {}\nexport async function POST() {}");
    await put(root, "src/app/page.tsx", "export default function P(){return null}");
    await put(root, "src/app/(shop)/cart/page.tsx", "export default function P(){return null}");
    await put(root, "src/lib/db.ts", "import { Pool } from 'pg';\nimport Stripe from 'stripe';\nexport const pool = new Pool();");
    await put(root, ".github/workflows/ci.yml", `name: CI
on: { push: { branches: [main] }, pull_request: {} }
jobs:
  lint:
    runs-on: ubuntu-latest
    steps: [{ run: npm run lint }]
  test:
    runs-on: ubuntu-latest
    steps: [{ run: npm test }]
  deploy:
    needs: [lint, test]
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: amondnet/vercel-action@v25
`);
    await put(root, "Dockerfile", "FROM node:22 AS build\nFROM node:22-slim\nEXPOSE 3000\n");
    await put(root, "docker-compose.yml", "services:\n  web:\n    build: .\n    ports: ['3000:3000']\n    depends_on: [db, cache]\n  db:\n    image: postgres:16\n  cache:\n    image: redis:7\n");
    await put(root, "infra/main.tf", 'resource "aws_s3_bucket" "assets" {}\nresource "aws_sqs_queue" "jobs" {}\nresource "aws_vpc" "main" {}\n');
    await put(root, "CODEOWNERS", "* @acme/everyone\n/src/app/api/ @acme/api\n");
    res = await scan(root);
  });
  afterAll(() => rm(root, { recursive: true, force: true }));

  it("produces a graph that passes integrity checks", () => expect(validateGraph(res.graph)).toEqual([]));
  it("streams stages and partial graphs before finishing", () => {
    expect(res.events.filter((e) => e === "graph").length).toBeGreaterThanOrEqual(4);
    expect(res.events.at(-1)).toBe("done");
  });
  it("gives every node at least one evidence ref", () => expect(res.graph.nodes.every((n) => n.evidence.length >= 1 && n.evidence[0].path)).toBe(true));
  it("finds the app as an L0 service with routes at L1", () => {
    const app = byLabel(res.graph, "shop")!;
    expect(app).toMatchObject({ level: 0, kind: "service" });
    expect(app.summary).toMatch(/Next\.js/);
    const routes = res.graph.nodes.filter((n) => n.parentId === app.id && n.kind === "endpoint").map((n) => n.label);
    expect(routes).toEqual(expect.arrayContaining(["GET /api/orders", "POST /api/orders", "PAGE /", "PAGE /cart"]));
  });
  it("cites file:line for routes", () => {
    const post = byLabel(res.graph, "POST /api/orders")!;
    expect(post.evidence[0]).toEqual({ path: "src/app/api/orders/route.ts", lines: "2" });
  });
  it("builds the workflow DAG: workflow L1, jobs L2, needs as edges", () => {
    const wf = byLabel(res.graph, "CI")!;
    expect(wf.level).toBe(1);
    const jobs = res.graph.nodes.filter((n) => n.parentId === wf.id);
    expect(jobs.map((j) => j.label).sort()).toEqual(["deploy", "lint", "test"]);
    const id = (l: string) => jobs.find((j) => j.label === l)!.id;
    const has = (a: string, b: string) => res.graph.edges.some((e) => e.from === id(a) && e.to === id(b));
    expect(has("lint", "deploy") && has("test", "deploy")).toBe(true);
    expect(wf.summary).toMatch(/push, pull_request/);
  });
  it("links the deploy job to its environment and target (lifted to siblings)", () => {
    expect(byLabel(res.graph, "production environment")).toBeTruthy();
    expect(byLabel(res.graph, "Deploys to Vercel")).toBeTruthy();
    const wf = byLabel(res.graph, "CI")!;
    expect(res.graph.edges.some((e) => e.from === wf.id && e.to === byLabel(res.graph, "production environment")!.id)).toBe(true);
  });
  it("detects datastores from code, compose and terraform without duplicates", () => {
    const pg = res.graph.nodes.filter((n) => n.label === "PostgreSQL");
    expect(pg).toHaveLength(1);
    expect(pg[0].evidence.length).toBeGreaterThan(1); // package.json + compose + code merged
    expect(byLabel(res.graph, "Redis")).toBeTruthy();
    expect(byLabel(res.graph, /S3 bucket: assets/)).toBeTruthy();
    expect(byLabel(res.graph, /SQS queue: jobs/)).toBeTruthy();
    expect(byLabel(res.graph, /vpc/i)).toBeUndefined(); // unmapped resource ignored
  });
  it("detects third-party services", () => {
    expect(byLabel(res.graph, "Stripe")?.parentId).toBe("cl:external");
    expect(byLabel(res.graph, "SendGrid")).toBeTruthy();
  });
  it("wires the app to its data stores at L0", () => {
    const app = byLabel(res.graph, "shop")!;
    expect(res.graph.edges.some((e) => e.from === app.id && e.to === "cl:data")).toBe(true);
    expect(res.graph.edges.some((e) => e.from === app.id && e.to === "cl:external")).toBe(true);
  });
  it("applies CODEOWNERS", () => expect(byLabel(res.graph, "GET /api/orders")?.owners).toEqual(["@acme/api"]));
  it("starts every node as 'unknown' because no live signal exists yet", () => expect(res.graph.nodes.every((n) => n.state === "unknown")).toBe(true));
});

describe("Python FastAPI monorepo", () => {
  let root: string;
  let res: Awaited<ReturnType<typeof scan>>;
  beforeAll(async () => {
    root = await mkdtemp(path.join(tmpdir(), "twin-py-"));
    await put(root, "package.json", JSON.stringify({ name: "root", private: true, workspaces: ["apps/*", "packages/*"] }));
    await put(root, "apps/web/package.json", JSON.stringify({ name: "@acme/web", dependencies: { next: "15", "@acme/ui": "*", "@acme/db": "*" } }));
    for (const lib of ["ui", "db", "config"]) await put(root, `packages/${lib}/package.json`, JSON.stringify({ name: `@acme/${lib}`, dependencies: lib === "db" ? { "drizzle-orm": "1" } : {} }));
    await put(root, "services/api/pyproject.toml", '[project]\nname = "api"\ndependencies = ["fastapi>=0.100", "sqlalchemy", "psycopg2-binary", "stripe", "celery"]\n');
    await put(root, "services/api/Dockerfile", "FROM python:3.12\nEXPOSE 8000\n");
    await put(root, "services/api/app/main.py", `from fastapi import FastAPI
import sqlalchemy
app = FastAPI()

@app.get("/health")
def health(): ...

@app.post("/items/{id}")
def create(id: int): ...
`);
    res = await scan(root);
  });
  afterAll(() => rm(root, { recursive: true, force: true }));

  it("passes integrity checks", () => expect(validateGraph(res.graph)).toEqual([]));
  it("does not treat the workspace root as a component", () => expect(byLabel(res.graph, "root")).toBeUndefined());
  it("folds 3+ internal libraries into one cluster", () => {
    const libs = byLabel(res.graph, "Shared packages")!;
    expect(libs.level).toBe(0);
    expect(res.graph.nodes.filter((n) => n.parentId === libs.id).map((n) => n.label).sort()).toEqual(["@acme/config", "@acme/db", "@acme/ui"]);
  });
  it("draws workspace dependencies between L0 nodes", () => {
    const web = byLabel(res.graph, "@acme/web")!;
    expect(res.graph.edges.some((e) => e.from === web.id && e.to === byLabel(res.graph, "Shared packages")!.id)).toBe(true);
  });
  it("finds FastAPI routes with tree-sitter and links Dockerfile", () => {
    const api = byLabel(res.graph, "api")!;
    expect(api.summary).toMatch(/FastAPI/);
    const routes = res.graph.nodes.filter((n) => n.parentId === api.id && n.kind === "endpoint").map((n) => n.label);
    expect(routes).toEqual(expect.arrayContaining(["GET /health", "POST /items/{id}"]));
    expect(res.graph.edges.some((e) => e.from === api.id && e.to === "cl:infra")).toBe(true);
  });
  it("maps python deps to datastores, queues and services", () => {
    expect(byLabel(res.graph, "PostgreSQL")).toBeTruthy();
    expect(byLabel(res.graph, "Celery task queue")).toBeTruthy();
    expect(byLabel(res.graph, "Stripe")).toBeTruthy();
  });
});

describe("degenerate repos", () => {
  it("returns an empty graph and a warning rather than failing", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "twin-empty-"));
    await put(root, "README.md", "# hi");
    const r = await scan(root);
    expect(r.graph.nodes).toEqual([]);
    expect(r.warnings.join()).toMatch(/No workflows/);
    await rm(root, { recursive: true, force: true });
  });
  it("survives malformed workflow yaml and json manifests", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "twin-bad-"));
    await put(root, ".github/workflows/x.yml", "jobs: [unclosed\n  : :");
    await put(root, "package.json", "{ not json");
    await put(root, "src/a.ts", "const = = ;");
    const r = await scan(root);
    expect(validateGraph(r.graph)).toEqual([]);
    await rm(root, { recursive: true, force: true });
  });
});

describe("pyproject dependency parsing", () => {
  it("handles extras with brackets inside the dependency array", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "twin-pyx-"));
    await put(root, "backend/pyproject.toml", '[project]\nname = "app"\ndependencies = [\n  "fastapi[standard]<1.0.0,>=0.114.2",\n  "psycopg[binary]<4.0.0",\n  "sqlmodel>=0.0.21",\n]\n');
    const { graph } = await scan(root);
    const svc = byLabel(graph, "backend");
    expect(svc?.summary).toMatch(/^FastAPI · 3 dependencies/);
    expect(byLabel(graph, "PostgreSQL")).toBeTruthy();
    await rm(root, { recursive: true, force: true });
  });
});

describe("FastAPI router prefixes", () => {
  it("prefixes routes registered on an APIRouter", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "twin-pfx-"));
    await put(root, "requirements.txt", "fastapi\n");
    await put(root, "app/users.py", 'from fastapi import APIRouter\nrouter = APIRouter(prefix="/users", tags=["users"])\n\n@router.get("/{id}")\ndef g(id): ...\n\n@router.post("/")\ndef c(): ...\n');
    const { graph } = await scan(root);
    const labels = graph.nodes.map((n) => n.label);
    expect(labels).toContain("GET /users/{id}");
    expect(labels).toContain("POST /users/");
    await rm(root, { recursive: true, force: true });
  });
});

describe("authenticated clone", () => {
  it("passes the token only through git config env: scoped to the host, never in a URL", () => {
    const env = gitAuthEnv("https://github.com/acme/private.git", "ghs_SECRET");
    expect(env.GIT_CONFIG_COUNT).toBe("1");
    expect(env.GIT_CONFIG_KEY_0).toBe("http.https://github.com/.extraheader");
    expect(Buffer.from(env.GIT_CONFIG_VALUE_0.replace("AUTHORIZATION: basic ", ""), "base64").toString()).toBe("x-access-token:ghs_SECRET");
    expect(JSON.stringify(Object.keys(env))).not.toContain("SECRET");
  });
  it("scopes to the repo's own host (GitHub Enterprise)", () => {
    expect(gitAuthEnv("https://ghe.corp.example/o/r.git", "t").GIT_CONFIG_KEY_0).toBe("http.https://ghe.corp.example/.extraheader");
  });
});
