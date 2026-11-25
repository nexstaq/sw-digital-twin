import { redactLine } from "@/lib/security/analyzers/secrets";

/**
 * Reading a few lines of source, only when the repository owner turned that on. What is read here never leaves the request: it is
 * checked for a visible mitigation and, for a patch, turned into a diff that is shown and thrown away. Nothing in this file stores
 * a line of source or sends one to a model.
 */

export interface Excerpt {
  path: string;
  /** line number of `lines[0]` */
  startLine: number;
  lines: string[];
}

export interface Mitigation { mitigated: boolean; why?: string }

const lineAt = (x: Excerpt, n: number) => x.lines[n - x.startLine] ?? "";
const before = (x: Excerpt, n: number, span = 14) => x.lines.slice(Math.max(0, n - x.startLine - span), Math.max(0, n - x.startLine));
const around = (x: Excerpt, n: number, span = 14) => x.lines.slice(Math.max(0, n - x.startLine - span), n - x.startLine + span);

/** `x = Number(...)`, `x = parseInt(...)`, a regex test, an integer check: the value is a number by the time it is used */
const numberLike = (name: string) => [
  new RegExp(String.raw`\b${name}\s*=\s*(?:Number|parseInt|parseFloat|BigInt)\s*\(`),
  new RegExp(String.raw`\b${name}\s*=\s*Math\.(?:trunc|floor|round|ceil)\s*\(`),
  new RegExp(String.raw`\b${name}\s*=\s*\+\s*[\w$.(]`),
  new RegExp(String.raw`Number\.isInteger\s*\(\s*${name}\s*\)`),
  new RegExp(String.raw`/\^?\\d[^/]*\$?/\.test\s*\(\s*${name}\s*\)`),
  new RegExp(String.raw`\b${name}\s*=\s*\w+\.(?:int|number)\s*\(`),
];

/**
 * Does the source show the input being made safe before it is used? A heuristic that errs toward "not mitigated": it only says yes
 * when it can see, in the lines just above, the value being forced to a number (SQL) or the path being confined (files).
 * It cannot see other files, so "not mitigated" means "not seen", and "mitigated" means "looks that way; read it".
 */
export function checkMitigation(ruleId: string, line: number, x: Excerpt): Mitigation {
  if (ruleId === "CODE/sql-injection") {
    const text = lineAt(x, line);
    const names = [...text.matchAll(/\$\{\s*([A-Za-z_$][\w$]*)\s*\}/g)].map((m) => m[1]);
    if (!names.length) return { mitigated: false };
    const above = before(x, line).join("\n");
    const unsafe = names.filter((n) => !numberLike(n).some((re) => re.test(above)));
    if (unsafe.length === 0) return { mitigated: true, why: `${names.join(", ")} ${names.length > 1 ? "are" : "is"} converted to a number before ${names.length > 1 ? "they are" : "it is"} put into the query` };
    return { mitigated: false };
  }
  if (ruleId === "CODE/path-traversal") {
    const w = around(x, line).join("\n");
    if (/\bbasename\s*\(/.test(w)) return { mitigated: true, why: "the file name is reduced to its last part with basename" };
    if (/\.includes\(\s*["']\.\.["']\s*\)/.test(w)) return { mitigated: true, why: "names containing .. are rejected" };
    if (/\bresolve\s*\(/.test(w) && /\.startsWith\s*\(/.test(w)) return { mitigated: true, why: "the resolved path is checked to stay inside the allowed folder" };
    return { mitigated: false };
  }
  return { mitigated: false };
}

// ---------------- patches: shown as a diff, never applied ----------------

export type PatchKind = "parameterise-query" | "confine-path";
export interface Patch { kind: PatchKind; diff: string }

const JS = /\.(?:[cm]?[jt]sx?)$/;

/** the position of the `)` that closes the `(` at `open`, skipping strings; -1 if there is none on this line */
function closeParen(s: string, open: number): number {
  let depth = 0, quote = "";
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    if (quote) { if (c === "\\") i++; else if (c === quote) quote = ""; continue; }
    if (c === '"' || c === "'" || c === "`") { quote = c; continue; }
    if (c === "(") depth++;
    else if (c === ")" && --depth === 0) return i;
  }
  return -1;
}

/** the top-level, comma-separated arguments of `s` (commas inside brackets or strings do not split) */
function splitArgs(s: string): string[] {
  const out: string[] = []; let depth = 0, quote = "", cur = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) { cur += c; if (c === "\\") { cur += s[++i] ?? ""; } else if (c === quote) quote = ""; continue; }
    if (c === '"' || c === "'" || c === "`") { quote = c; cur += c; continue; }
    if ("([{".includes(c)) depth++; else if (")]}".includes(c)) depth--;
    if (c === "," && depth === 0) { out.push(cur); cur = ""; } else cur += c;
  }
  out.push(cur);
  return out;
}

const USER_INPUT = /\b(req|request|params|query|body|searchParams|headers|cookies|formData|userInput)\b/;

/** SQL built in a template string inside `.query(` or `.execute(`, rewritten to placeholders and a values list */
function parameterise(line: string): string | null {
  const m = /(\.(?:query|execute)\()\s*`([^`]*)`/.exec(line);
  if (!m || !m[2].includes("${")) return null;
  const values: string[] = [];
  let sql = "";
  let rest = m[2];
  while (rest.length) {
    const open = rest.indexOf("${");
    if (open < 0) { sql += rest; break; }
    sql += rest.slice(0, open);
    let depth = 1, i = open + 2;
    for (; i < rest.length && depth; i++) { if (rest[i] === "{") depth++; else if (rest[i] === "}") depth--; }
    if (depth) return null; // an unbalanced ${ }: leave it alone
    values.push(rest.slice(open + 2, i - 1).trim());
    sql += `$${values.length}`;
    rest = rest.slice(i);
  }
  const start = line.indexOf(m[0]);
  const end = start + m[0].length;
  return `${line.slice(0, start)}${m[1]}${JSON.stringify(sql)}, [${values.join(", ")}]${line.slice(end)}`;
}

/** `path.join(base, <request data>)` rewritten so the request data can only be a file name */
function confinePath(line: string): string | null {
  const at = line.search(/\bpath\.join\s*\(/);
  if (at < 0) return null;
  const open = line.indexOf("(", at);
  const close = closeParen(line, open);
  if (close < 0) return null;
  const args = splitArgs(line.slice(open + 1, close));
  if (args.length < 2) return null;
  let changed = false;
  const out = args.map((a, i) => {
    if (i === 0 || !USER_INPUT.test(a) || /\bbasename\(/.test(a)) return a;
    changed = true;
    const lead = /^\s*/.exec(a)![0];
    return `${lead}path.basename(${a.trim()})`;
  });
  return changed ? `${line.slice(0, open + 1)}${out.join(",")}${line.slice(close)}` : null;
}

function unified(x: Excerpt, line: number, replacement: string): string {
  const from = Math.max(x.startLine, line - 3), to = Math.min(x.startLine + x.lines.length - 1, line + 3);
  const body: string[] = [];
  for (let n = from; n <= to; n++) {
    if (n === line) { body.push(`-${lineAt(x, n)}`, `+${replacement}`); } else body.push(` ${lineAt(x, n)}`);
  }
  const count = to - from + 1;
  return [`--- a/${x.path}`, `+++ b/${x.path}`, `@@ -${from},${count} +${from},${count} @@`, ...body].join("\n");
}

export function proposePatch(ruleId: string, line: number, x: Excerpt): Patch | null {
  if (!JS.test(x.path)) return null;
  const text = lineAt(x, line);
  if (!text) return null;
  const rewrite = ruleId === "CODE/sql-injection" ? parameterise(text) : ruleId === "CODE/path-traversal" ? confinePath(text) : null;
  if (!rewrite || rewrite === text) return null;
  const patch: Patch = { kind: ruleId === "CODE/sql-injection" ? "parameterise-query" : "confine-path", diff: unified(x, line, rewrite) };
  return validateDiff(patch.diff, x.path) ? patch : null;
}

/** A proposed diff is text to look at, so it is held to a short list of rules before anyone sees it. */
export function validateDiff(diff: string, path: string): boolean {
  const lines = diff.split("\n");
  if (lines[0] !== `--- a/${path}` || lines[1] !== `+++ b/${path}` || !/^@@ -\d+,\d+ \+\d+,\d+ @@$/.test(lines[2] ?? "")) return false;
  if (lines.filter((l) => l.startsWith("@@")).length !== 1) return false;
  const body = lines.slice(3);
  if (body.some((l) => l !== "" && !/^[ +-]/.test(l))) return false;
  const added = body.filter((l) => l.startsWith("+"));
  const removed = body.filter((l) => l.startsWith("-"));
  if (added.length > 10 || removed.length > 10 || added.length === 0) return false;
  for (const a of added) {
    if (/https?:\/\/|www\./i.test(a)) return false;            // no new addresses
    if (redactLine(a) !== a) return false;                       // nothing that looks like a secret
    if (/\b(?:require|import)\s*\(|^\+\s*import\b|child_process|\beval\s*\(/.test(a)) return false; // no new code paths
  }
  return true;
}
