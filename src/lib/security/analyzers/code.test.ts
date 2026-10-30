import { describe, expect, it } from "vitest";
import { analyzeCode } from "./code";
import type { SecurityContext } from "../types";

const run = (files: Record<string, string>) => analyzeCode({ repo: "a/b", files: Object.keys(files), read: async (p) => files[p] ?? null } as SecurityContext);
const rules = async (src: string, path = "src/a.ts") => (await run({ [path]: src })).map((f) => f.ruleId).sort();
const one = async (src: string, path = "src/a.ts") => { const f = await run({ [path]: src }); expect(f, src).toHaveLength(1); return f[0]; };
const clean = async (src: string, path = "src/a.ts") => expect(await rules(src, path), src).toEqual([]);

describe("SQL injection (JS/TS)", () => {
  it("flags a template string with request data, pinned to the line, as high", async () => {
    const f = await one("const x = 1;\napp.get('/u', (req) => {\n  db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);\n});");
    expect(f).toMatchObject({ ruleId: "CODE/sql-injection", severity: "high", category: "code", line: 3, confidence: "medium", cwe: ["CWE-89"] });
    expect(f.title).toBe("SQL built from request data");
  });
  it("flags concatenation, but only medium when the value is not obviously from the request", async () => {
    const f = await one('pool.query("SELECT * FROM t WHERE name = \'" + name + "\'");');
    expect(f).toMatchObject({ severity: "medium", confidence: "low" });
  });
  it("does NOT flag parameterised queries or tagged templates (the safe form in Drizzle/Prisma/postgres.js)", async () => {
    await clean("db.query('SELECT * FROM t WHERE id = $1', [id]);");
    await clean("const r = await sql`SELECT * FROM t WHERE id = ${id}`;");
    await clean("await prisma.$queryRaw`SELECT * FROM t WHERE id = ${id}`;");
    await clean("db.query(QUERY);");
    await clean("db.query('SELECT 1');");
  });
  it("flags the explicitly unsafe Prisma API", async () => {
    expect(await rules("await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE x = ${req.body.x}`);")).toEqual(["CODE/sql-injection"]);
  });
  it("ignores non-SQL strings passed to query-ish methods", async () => {
    await clean("router.query(`hello ${name}`);");
  });
});

describe("command injection and eval", () => {
  it("exec with a template or concatenation is flagged; with request data it is high", async () => {
    const f = await one("import { exec } from 'child_process';\nexec(`convert ${req.body.file} out.png`);");
    expect(f).toMatchObject({ ruleId: "CODE/command-injection", severity: "high", line: 2 });
    expect((await one("import { execSync } from 'child_process';\nexecSync('ls ' + dir);")).severity).toBe("medium");
  });
  it("execFile with an argument array, and exec of a fixed string, are fine", async () => {
    await clean("import { execFile, exec } from 'child_process';\nexecFile('convert', [file, 'out.png']);\nexec('git status');");
  });
  it("spawn is flagged only with shell: true", async () => {
    expect(await rules("import { spawn } from 'child_process';\nspawn(cmd, args, { shell: true });")).toEqual(["CODE/command-injection"]);
    await clean("import { spawn } from 'child_process';\nspawn(cmd, args);");
  });
  it("a file that never imports child_process is not judged on a method called exec", async () => {
    await clean("regex.exec('abc' + x);\ndb.exec(`x ${y}`);");
  });
  it("eval and new Function with variable text, not with a literal", async () => {
    expect(await rules("eval(code);")).toEqual(["CODE/eval"]);
    expect(await rules("const f = new Function('a', body);")).toEqual(["CODE/eval"]);
    expect((await one("eval(req.body.expr);")).severity).toBe("high");
    await clean("eval('1 + 1');");
    await clean("JSON.parse(text);");
  });
});

describe("XSS", () => {
  it("dangerouslySetInnerHTML with a variable; not with a sanitised or literal value", async () => {
    expect(await rules("const a = <div dangerouslySetInnerHTML={{ __html: html }} />;", "src/a.tsx")).toEqual(["CODE/xss-react"]);
    await clean("const a = <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;", "src/a.tsx");
    await clean("const a = <div dangerouslySetInnerHTML={{ __html: '<b>hi</b>' }} />;", "src/a.tsx");
  });
  it("innerHTML assignment and document.write with variables, not with literals or sanitised values", async () => {
    expect(await rules("el.innerHTML = userHtml;")).toEqual(["CODE/xss-dom"]);
    expect(await rules("document.write(markup);")).toEqual(["CODE/xss-dom"]);
    await clean("el.innerHTML = '<b>static</b>';");
    await clean("el.innerHTML = sanitize(userHtml);");
    await clean("el.textContent = userText;");
  });
});

describe("SSRF, path traversal, redirect", () => {
  it("fetching a URL taken from the request is flagged; a fixed origin with a request value in the PATH is not", async () => {
    expect(await rules("await fetch(req.query.url);")).toEqual(["CODE/ssrf"]);
    expect(await rules("await axios.get(searchParams.get('target'));")).toEqual(["CODE/ssrf"]);
    await clean("await fetch(`https://api.example.com/users/${req.query.id}`);");
    await clean("await fetch('https://api.example.com/x');");
    await clean("await fetch(url);"); // an unknown variable is not evidence of attacker control
  });
  it("file access with request data is flagged unless the path is normalised", async () => {
    expect(await rules("fs.readFile(path.join(base, req.params.name), cb);")).toEqual(["CODE/path-traversal"]);
    await clean("fs.readFile(path.join(base, path.basename(req.params.name)), cb);");
    await clean("fs.readFile('./static/a.txt', cb);");
  });
  it("redirects to a request value are low-confidence findings; fixed targets are fine", async () => {
    const f = await one("res.redirect(req.query.next);");
    expect(f).toMatchObject({ ruleId: "CODE/open-redirect", confidence: "low" });
    await clean("res.redirect('/login');");
  });
});

describe("crypto and configuration", () => {
  it("MD5/SHA-1 is low generally and medium near a password", async () => {
    expect((await one("crypto.createHash('md5').update(file).digest('hex');")).severity).toBe("low");
    expect((await one("const h = crypto.createHash('sha1').update(password).digest('hex');")).severity).toBe("medium");
    await clean("crypto.createHash('sha256').update(x).digest('hex');");
  });
  it("Math.random is flagged only where the value is a security token", async () => {
    expect(await rules("const resetToken = Math.random().toString(36);")).toEqual(["CODE/insecure-random"]);
    await clean("const jitter = Math.random() * 100;");
  });
  it("disabled TLS verification, in every spelling", async () => {
    expect(await rules("https.request({ host, rejectUnauthorized: false });")).toEqual(["CODE/tls-verification-disabled"]);
    expect(await rules("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';")).toEqual(["CODE/tls-verification-disabled"]);
    await clean("https.request({ host, rejectUnauthorized: true });");
  });
  it("cookies: httpOnly/secure false inside cookie options only", async () => {
    expect(await rules("res.cookie('sid', v, { httpOnly: false });")).toEqual(["CODE/insecure-cookie"]);
    await clean("res.cookie('sid', v, { httpOnly: true, secure: true });");
    expect(await rules("const cookieOptions = { secure: false };")).toEqual(["CODE/insecure-cookie"]);
    expect(await rules("session({ cookie: { httpOnly: false } });")).toEqual(["CODE/insecure-cookie"]);
    await clean("const opts = { secure: false };"); // not obviously a cookie
  });
  it("JWT: the none algorithm is critical; a literal signing secret is high; an env secret is fine", async () => {
    expect((await one("jwt.verify(t, key, { algorithms: ['HS256', 'none'] });\nimport jwt from 'jsonwebtoken';")).severity).toBe("critical");
    const f = await one("import jwt from 'jsonwebtoken';\nconst t = jwt.sign({ id }, 'supersecretvalue');");
    expect(f).toMatchObject({ ruleId: "CODE/hardcoded-jwt-secret", severity: "high" });
    expect(JSON.stringify(f)).not.toContain("supersecretvalue"); // the literal is never copied into a finding
    await clean("import jwt from 'jsonwebtoken';\nconst t = jwt.sign({ id }, process.env.JWT_SECRET);");
  });
  it("CORS wildcard with credentials", async () => {
    expect(await rules("app.use(cors({ origin: '*', credentials: true }));")).toEqual(["CODE/cors-wildcard-credentials"]);
    await clean("app.use(cors({ origin: 'https://app.example.com', credentials: true }));");
    await clean("app.use(cors({ origin: '*' }));");
  });
});

describe("Python", () => {
  it("SQL in an f-string or % format is flagged; parameters are not", async () => {
    expect(await rules('cur.execute(f"SELECT * FROM t WHERE id = {uid}")', "app.py")).toEqual(["CODE/sql-injection"]);
    expect(await rules('cur.execute("SELECT * FROM t WHERE id = %s" % uid)', "app.py")).toEqual(["CODE/sql-injection"]);
    expect(await rules('cur.execute("SELECT * FROM t WHERE id = {}".format(uid))', "app.py")).toEqual(["CODE/sql-injection"]);
    await clean('cur.execute("SELECT * FROM t WHERE id = %s", (uid,))', "app.py");
    await clean('cur.execute("SELECT 1")', "app.py");
  });
  it("shell commands and eval", async () => {
    expect(await rules("import os\nos.system('rm ' + path)", "a.py")).toEqual(["CODE/command-injection"]);
    expect(await rules("import subprocess\nsubprocess.run(cmd, shell=True)", "a.py")).toEqual(["CODE/command-injection"]);
    await clean("import subprocess\nsubprocess.run(['ls', path])", "a.py");
    await clean("import subprocess\nsubprocess.run('ls -la', shell=True)", "a.py");
    expect(await rules("eval(expr)", "a.py")).toEqual(["CODE/eval"]);
    await clean("eval('1+1')", "a.py");
  });
  it("pickle, yaml.load and verify=False and debug=True", async () => {
    expect(await rules("import pickle\npickle.loads(data)", "a.py")).toEqual(["CODE/unsafe-deserialization"]);
    expect(await rules("import yaml\nyaml.load(s)", "a.py")).toEqual(["CODE/unsafe-yaml"]);
    await clean("import yaml\nyaml.safe_load(s)\nyaml.load(s, Loader=yaml.SafeLoader)", "a.py");
    expect(await rules("import requests\nrequests.get(u, verify=False)", "a.py")).toEqual(["CODE/tls-verification-disabled"]);
    await clean("import requests\nrequests.get(u)", "a.py");
    expect(await rules("app.run(debug=True)", "a.py")).toEqual(["CODE/debug-mode"]);
    await clean("app.run(debug=False)", "a.py");
  });
});

describe("what the analyzer skips, and how it identifies findings", () => {
  it("skips tests, declaration files, minified bundles and generated code", async () => {
    const f = await run({
      "src/a.test.ts": "eval(x);", "tests/b.ts": "eval(x);", "types/c.d.ts": "eval(x);", "dist/app.min.js": "eval(x);", "src/generated/d.ts": "eval(x);",
      "big.js": "var a=1;" + "x".repeat(25_000) + ";eval(code);\n" + "y".repeat(4_000),
    });
    expect(f).toEqual([]);
  });
  it("a syntax error does not stop the rest of the repository being analysed", async () => {
    const f = await run({ "broken.ts": "function ((( {", "ok.ts": "eval(code);" });
    expect(f.map((x) => x.path)).toEqual(["ok.ts"]);
  });
  it("ids survive line shifts, and the same issue repeated is one finding with every line", async () => {
    const a = await one("eval(code);");
    const b = await one("// a\n// b\neval(code);");
    expect(b.id).toBe(a.id);
    expect(b.line).toBe(3);
    const twice = await run({ "x.ts": "eval(code);\nconst y = 1;\neval(code);" });
    expect(twice).toHaveLength(1);
    expect(twice[0].detail.lines).toEqual([1, 3]);
  });
  it("every finding carries a reason, a fix and a standard, so none is a bare accusation", async () => {
    const all = await run({
      "a.ts": "import { exec } from 'child_process';\neval(c);\nexec(`x ${req.body.a}`);\ndb.query(`SELECT ${req.query.a}`);\nfetch(req.query.u);\nel.innerHTML = h;\nhttps.get({ rejectUnauthorized: false });",
      "b.py": "import pickle, yaml\npickle.loads(d)\nyaml.load(s)",
    });
    expect(all.length).toBeGreaterThanOrEqual(8);
    for (const f of all) { expect(f.reason.length, f.ruleId).toBeGreaterThan(40); expect(f.fix.length, f.ruleId).toBeGreaterThan(20); expect(f.cwe.length, f.ruleId).toBeGreaterThan(0); expect(f.owasp, f.ruleId).toBeTruthy(); }
  });
});

describe("safe idioms seen on a real Next.js app are NOT flagged", () => {
  it("a client component fetching its own relative API is not SSRF", async () => {
    await clean('"use client";\nexport function V() { fetch(`/api/panchangam?${query.toString()}`, { signal: ctl.signal }); }', "src/v.tsx");
    await clean("// c\n'use client'\nfetch(req.query.url);", "src/v2.tsx"); // browser-side: cannot reach internal services on the server's behalf
    await clean("fetch(`/api/x?${req.query.q}`);"); // a relative path stays on this server's own origin
  });
  it("...but the same on the server, with the request choosing the host, still is", async () => {
    expect(await rules("export async function GET(req) { await fetch(`${req.query.base}/x`); }")).toEqual(["CODE/ssrf"]);
  });
  it("JSON-LD with '<' escaped is the standard safe idiom; without the escape it is flagged", async () => {
    await clean('const a = <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(ld).replace(/</g, "\\u003c") }} />;', "src/p.tsx");
    const f = await one('const a = <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(ld) }} />;', "src/p.tsx");
    expect(f.title).toMatch(/without escaping/);
    expect(f.fix).toContain("u003c");
  });
  it("a module-level constant string passed to a sink is not user data", async () => {
    await clean('const THEME_SCRIPT = "document.documentElement.dataset.theme = 1";\nconst a = <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />;', "src/l.tsx");
    await clean("const CODE = `1 + 1`;\neval(CODE);");
    await clean("const HTML = '<b>x</b>';\nel.innerHTML = HTML;");
    expect(await rules("const HTML = `<b>${x}</b>`;\nel.innerHTML = HTML;")).toEqual(["CODE/xss-dom"]); // a built string is NOT a constant
  });
});
