import { describe, expect, it } from "vitest";
import { analyzeSecrets, dbUrlParts, entropy, looksLikeIdentifier, maskSecret, redactLine } from "./secrets";
import type { SecurityContext } from "../types";

// Credentials are assembled at runtime so no real-looking secret is ever written in the repo (and push protection stays quiet).
const AWS = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE";
const GH = "ghp" + "_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
const STRIPE = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc";
const KEY = "-----BEGIN RSA PRIVATE " + "KEY-----";
const RAND = "q7Zp4Lm9Xv2Kd8Tn5Rb3Wc6Yh1Jf0Ga";

const ctx = (files: Record<string, string>): SecurityContext => ({ repo: "a/b", files: Object.keys(files), read: async (p) => files[p] ?? null });
const run = (files: Record<string, string>) => analyzeSecrets(ctx(files));

describe("analyzeSecrets", () => {
  it("finds provider-format secrets, pins the line, and never keeps the value", async () => {
    const f = await run({ "src/config.ts": `const a = 1;\nexport const key = "${AWS}";\n`, "ops/deploy.sh": `export GH=${GH}\n`, "pay.ts": `const s = "${STRIPE}";` });
    expect(f.map((x) => x.detail.secretKind).sort()).toEqual(["AWS access key ID", "GitHub token", "Stripe live secret key"]);
    const aws = f.find((x) => x.detail.secretKind === "AWS access key ID")!;
    expect(aws).toMatchObject({ path: "src/config.ts", line: 2, severity: "critical", category: "secret", cwe: ["CWE-798"] });
    expect(JSON.stringify(f)).not.toContain(AWS);
    expect(JSON.stringify(f)).not.toContain(GH);
    expect(aws.detail.masked).toBe("AKIA…(20 chars)");
  });

  it("flags a committed private key", async () => {
    const [f] = await run({ "id.pem": `${KEY}\nMIIE...\n` });
    expect(f).toMatchObject({ severity: "critical", detail: { secretKind: "Private key" }, line: 1 });
  });

  it("catches a hard-coded credential, but not placeholders, env lookups or low-entropy values", async () => {
    const hit = await run({ "a.ts": `const password = "${RAND}";` });
    expect(hit).toHaveLength(1);
    expect(hit[0]).toMatchObject({ severity: "medium", detail: { secretKind: "Hard-coded credential" } });
    const quiet = await run({
      "b.ts": `const apiKey = process.env.API_KEY || "abcdefghijkl";\nconst token = "your_token_here_please";\nconst secret = "xxxxxxxxxxxxxxxx";\nconst password = "aaaaaaaaaaaaaaaa";`,
      "c.py": `API_KEY = os.environ["API_KEY"]`,
    });
    expect(quiet).toHaveLength(0);
  });

  it("downgrades test fixtures and templates instead of crying wolf", async () => {
    const f = await run({ "tests/auth.test.ts": `const k = "${AWS}";`, ".env.example": `AWS=${AWS}\nPASSWORD="${RAND}"` });
    const t = f.find((x) => x.path.startsWith("tests/"))!;
    expect(t).toMatchObject({ severity: "high", confidence: "low" }); // critical -> high
    expect(t.reason).toMatch(/test or fixture/);
    expect(f.find((x) => x.path === ".env.example")?.confidence).toBe("low");
    expect(f.filter((x) => x.path === ".env.example" && x.detail.secretKind === "Hard-coded credential")).toHaveLength(0);
  });

  it("skips lockfiles, minified bundles and binaries", async () => {
    const f = await run({ "package-lock.json": `"integrity": "${AWS}"`, "app.min.js": AWS, "x.png": AWS, "bin.dat": `\u0000${AWS}` });
    expect(f).toHaveLength(0);
  });

  it("the same secret on two lines is one finding; its id survives edits above it", async () => {
    const a = await run({ "c.ts": `x\nconst k = "${AWS}";\nconst k2 = "${AWS}";` });
    expect(a).toHaveLength(1);
    const b = await run({ "c.ts": `// added\n// lines\nx\nconst k = "${AWS}";` });
    expect(b[0].id).toBe(a[0].id);
  });

  it("detects a database URL with a password", async () => {
    const [f] = await run({ ".env": `DATABASE_URL=postgres://app:${RAND}@db.internal:5432/main` });
    expect(f.detail.secretKind).toBe("Database URL with password");
  });
});

describe("helpers", () => {
  it("entropy separates random from repetitive, and masking reveals almost nothing", () => {
    expect(entropy(RAND)).toBeGreaterThan(3.8);
    expect(entropy("aaaaaaaaaaaaaaaa")).toBe(0);
    expect(maskSecret(AWS)).toBe("AKIA…(20 chars)");
  });
  it("redactLine blanks secrets before any code excerpt is shown", () => {
    expect(redactLine(`const k = "${AWS}";`)).not.toContain(AWS);
    expect(redactLine(`const k = "${AWS}";`)).toContain("redacted");
    expect(redactLine(`password: "${RAND}"`)).not.toContain(RAND);
    expect(redactLine("const a = 1;")).toBe("const a = 1;");
  });
});

describe("false positives seen on a real repository", () => {
  it("a local dev database with a throwaway password (even in a comment) is not a finding", async () => {
    const f = await run({
      "scripts/dev-db.ts": "// Prints DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5433/postgres\n",
      "docker-compose.dev.yml": "DATABASE_URL: postgres://app:password@db:5432/app\n",
      "README-ish.ts": "const u = 'postgres://user:user@localhost/db';",
    });
    expect(f).toEqual([]);
  });
  it("a local host with a REAL-looking password is a low note; a remote host is still high", async () => {
    const local = await run({ "a.ts": `const u = "postgres://app:${RAND}@localhost:5432/app";` });
    expect(local).toHaveLength(1);
    expect(local[0]).toMatchObject({ severity: "low", detail: { secretKind: "Database URL with password" } });
    const remote = await run({ "b.ts": `const u = "postgres://app:${RAND}@prod-db.example.net:5432/app";` });
    expect(remote[0].severity).toBe("high");
    const weakRemote = await run({ "c.ts": `const u = "postgres://admin:changeme@prod-db.example.net:5432/app";` });
    expect(weakRemote[0].severity).toBe("low"); // a placeholder password cannot leak much, but a real host deserves a look
  });
  it("cookie, header and env-var NAMES are not credentials", async () => {
    const f = await run({ "middleware.ts": `const token = "authjs.session-token";\nconst k = { apiKey: "x-api-key-header-name" };\nconst secret = "next-auth.csrf-token";` });
    expect(f).toEqual([]);
    expect(["authjs.session-token", "x-api-key", "__Secure-next-auth.session-token"].every(looksLikeIdentifier)).toBe(true);
    expect(looksLikeIdentifier(RAND)).toBe(false);
    expect(looksLikeIdentifier("abc-123-def")).toBe(false);
  });
  it("values that announce themselves as test data are skipped, real-looking ones are not", async () => {
    const f = await run({ "auth.ts": `const SECRET = "test-secret-for-ci-runs";\nconst password = "${RAND}";` });
    expect(f).toHaveLength(1);
    expect(f[0].line).toBe(2);
  });
  it("dbUrlParts extracts host/user/password and tolerates IPv6", () => {
    expect(dbUrlParts("DATABASE_URL=postgres://u:p@127.0.0.1:5433/db")).toEqual({ user: "u", password: "p", host: "127.0.0.1" });
    expect(dbUrlParts("redis://default:pw@[::1]:6379")?.host).toBe("[::1]");
    expect(dbUrlParts("no url here")).toBeNull();
  });
});
