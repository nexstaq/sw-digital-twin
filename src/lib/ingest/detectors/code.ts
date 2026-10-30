import type { SyntaxNode } from "web-tree-sitter";
import { DATASTORE_LIBS, EXTERNAL_LIBS } from "../knowledge";
import { createParsers, langFor } from "../parse";
import type { Detector, RawEdge, RawNode } from "../types";
import { baseOf, dirOf, lines, manifestDirs, owningDir, pkgId, slug } from "../util";
import { readPackageNames } from "./packages";

const METHODS = ["get", "post", "put", "delete", "patch", "head", "options", "all"];
const ROUTER_OBJ = /^(app|router|server|api|route|routes|r|fastify|hono|\w*[rR]outer|\w*[aA]pp)$/;
const MAX_SOURCE_FILES = 1500;
const MAX_ROUTES_PER_PKG = 300;
const GROUP_THRESHOLD = 12;

interface Route { method: string; path: string; file: string; line: number }

/** Next.js file-system routing: app/**\/route.ts, app/**\/page.tsx, pages/** */
function nextRoutes(file: string, text: string): Route[] {
  const m = /(?:^|\/)(app|pages)\/(.*)$/.exec(file);
  if (!m) return [];
  const [, kind, rest] = m;
  const segs = rest.split("/");
  const leaf = segs.pop()!;
  const clean = segs.filter((s) => !/^\(.*\)$/.test(s) && !s.startsWith("@"));
  const base = "/" + clean.join("/");
  const stem = leaf.replace(/\.(tsx?|jsx?|mjs)$/, "");
  if (kind === "app") {
    if (stem === "route") {
      return [...text.matchAll(/export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/g)].map((x) => ({
        method: x[1], path: base, file, line: text.slice(0, x.index).split("\n").length,
      }));
    }
    if (stem === "page") return [{ method: "PAGE", path: base, file, line: 1 }];
    return [];
  }
  if (stem.startsWith("_")) return [];
  const p = stem === "index" ? base : `${base === "/" ? "" : base}/${stem}`;
  return [{ method: segs[0] === "api" ? "API" : "PAGE", path: p || "/", file, line: 1 }];
}

/** NestJS decorators: regex over source (decorators are noisy to walk). */
function nestRoutes(file: string, text: string): Route[] {
  const prefix = /@Controller\(\s*['"`]([^'"`]*)['"`]/.exec(text)?.[1];
  if (prefix === undefined) return [];
  return [...text.matchAll(/@(Get|Post|Put|Delete|Patch)\(\s*(?:['"`]([^'"`]*)['"`])?\s*\)/g)].map((x) => ({
    method: x[1].toUpperCase(), path: "/" + [prefix, x[2]].filter(Boolean).join("/").replace(/\/+/g, "/").replace(/^\//, ""),
    file, line: text.slice(0, x.index).split("\n").length,
  }));
}

const strArg = (call: SyntaxNode): string | null => {
  const args = call.childForFieldName("arguments");
  const first = args?.namedChildren[0];
  if (!first) return null;
  if (first.type === "string" || first.type === "template_string") return first.text.replace(/^['"`]|['"`]$/g, "");
  return null;
};

export const codeDetector: Detector = {
  name: "Source code",
  async detect(ctx) {
    const nodes: RawNode[] = [];
    const edges: RawEdge[] = [];
    const dirs = manifestDirs(ctx.files);
    const names = await readPackageNames(ctx, dirs);
    const parsers = await createParsers();
    const routesByPkg = new Map<string, Route[]>();
    const entryByPkg = new Map<string, string[]>();
    const seenLib = new Set<string>();

    const source = ctx.files.filter((f) => langFor(f) && !/\.(test|spec|d)\.[tj]sx?$|(^|\/)(__tests__|tests?|e2e|fixtures?|node_modules)\//.test(f)).slice(0, MAX_SOURCE_FILES);

    for (const file of source) {
      const dir = owningDir(file, dirs);
      if (dir === undefined) continue;
      const pid = pkgId(dir);
      const lang = langFor(file)!;
      const text = await ctx.read(file);
      if (!text) continue;
      const routes = routesByPkg.get(pid) ?? [];

      // entrypoints, by convention
      const rel = dir ? file.slice(dir.length + 1) : file;
      if (/^(src\/)?(main|index|server|app|manage|wsgi|asgi|worker)\.(ts|js|mjs|py|tsx)$/.test(rel) || /^cmd\/[^/]+\/main\.go$/.test(rel)) {
        entryByPkg.set(pid, [...(entryByPkg.get(pid) ?? []), file]);
      }

      routes.push(...nextRoutes(file, text), ...nestRoutes(file, text));

      let tree;
      try { tree = parsers.parse(lang, text); } catch { routesByPkg.set(pid, routes); continue; }

      const noteLib = (spec: string, line: number) => {
        const root = lang === "python" ? spec.split(".")[0].toLowerCase().replace(/_/g, "-") : spec.startsWith("@") ? spec.split("/").slice(0, 2).join("/") : spec.split("/")[0];
        const lookups = lang === "python" ? [root, root === "psycopg2" ? "psycopg2" : root] : [spec, root];
        const ev = [{ path: file, lines: lines(line) }];
        for (const k of lookups) {
          const ds = DATASTORE_LIBS[k];
          if (ds && !seenLib.has(`${pid}|${ds.label}`)) {
            seenLib.add(`${pid}|${ds.label}`);
            nodes.push({ id: `ds:${slug(ds.label)}`, kind: ds.kind, group: "data", label: ds.label, summary: `Accessed from code (imports ${k}).`, evidence: ev });
            edges.push({ from: pid, to: `ds:${slug(ds.label)}`, kind: ds.kind === "queue" ? "publishes" : "reads" });
          }
          const ex = EXTERNAL_LIBS[k];
          if (ex && !seenLib.has(`${pid}|${ex}`)) {
            seenLib.add(`${pid}|${ex}`);
            nodes.push({ id: `ext:${slug(ex)}`, kind: "external", group: "external", label: ex, summary: `Called from code (imports ${k}).`, evidence: ev });
            edges.push({ from: pid, to: `ext:${slug(ex)}`, kind: "calls" });
          }
        }
        const target = names.get(spec) ?? names.get(root);
        if (target !== undefined && target !== dir) edges.push({ from: pid, to: pkgId(target), kind: "depends_on" });
      };

      if (lang === "python") {
        for (const n of tree.rootNode.descendantsOfType(["import_statement", "import_from_statement"])) {
          const mod = n.type === "import_from_statement" ? n.childForFieldName("module_name")?.text : n.namedChildren[0]?.text.split(" as ")[0];
          if (mod && !mod.startsWith(".")) noteLib(mod, n.startPosition.row + 1);
        }
        // APIRouter(prefix="/users") in the same file prefixes every route registered on that router
        const prefixes = new Map<string, string>();
        for (const m of text.matchAll(/(\w+)\s*=\s*APIRouter\([^)]*?prefix\s*=\s*["']([^"']*)["']/g)) prefixes.set(m[1], m[2]);
        for (const d of tree.rootNode.descendantsOfType("decorator")) {
          const m = /^@\s*(\w+)\.(get|post|put|delete|patch|route|websocket)\(\s*(['"])(.*?)\3/.exec(d.text);
          if (m) {
            const full = `${prefixes.get(m[1]) ?? ""}${m[4]}` || "/";
            routes.push({ method: m[2] === "route" ? "ANY" : m[2].toUpperCase(), path: full.startsWith("/") ? full : `/${full}`, file, line: d.startPosition.row + 1 });
          }
        }
        if (/(^|\/)urls\.py$/.test(file)) {
          for (const c of tree.rootNode.descendantsOfType("call")) {
            const fn = c.childForFieldName("function")?.text;
            if (fn === "path" || fn === "re_path") {
              const a = c.childForFieldName("arguments")?.namedChildren[0];
              if (a?.type === "string") routes.push({ method: "ANY", path: "/" + a.text.replace(/^[rbf]*['"]|['"]$/g, "").replace(/^\^|\$$/g, ""), file, line: c.startPosition.row + 1 });
            }
          }
        }
      } else {
        for (const n of tree.rootNode.descendantsOfType("import_statement")) {
          const src = n.childForFieldName("source")?.text.replace(/^['"`]|['"`]$/g, "");
          if (src && !src.startsWith(".")) noteLib(src, n.startPosition.row + 1);
        }
        for (const c of tree.rootNode.descendantsOfType("call_expression")) {
          const fn = c.childForFieldName("function");
          if (fn?.type === "identifier" && fn.text === "require") {
            const s = strArg(c);
            if (s && !s.startsWith(".")) noteLib(s, c.startPosition.row + 1);
          } else if (fn?.type === "member_expression") {
            const obj = fn.childForFieldName("object")?.text ?? "";
            const prop = fn.childForFieldName("property")?.text ?? "";
            if (METHODS.includes(prop) && ROUTER_OBJ.test(obj)) {
              const p = strArg(c);
              if (p?.startsWith("/")) routes.push({ method: prop.toUpperCase(), path: p, file, line: c.startPosition.row + 1 });
            }
          }
        }
      }
      routesByPkg.set(pid, routes);
    }

    // ---- turn findings into L1/L2 nodes ----
    for (const [pid, all] of routesByPkg) {
      const seen = new Set<string>();
      const routes = all.filter((r) => { const k = `${r.method} ${r.path}`; return seen.has(k) ? false : (seen.add(k), true); }).slice(0, MAX_ROUTES_PER_PKG);
      const groups = new Map<string, Route[]>();
      for (const r of routes) {
        const seg = r.path.split("/").filter(Boolean)[0] ?? "/";
        groups.set(seg, [...(groups.get(seg) ?? []), r]);
      }
      const grouped = routes.length > GROUP_THRESHOLD;
      const routeNode = (r: Route, parent: string): RawNode => ({
        id: `route:${pid}:${r.method}:${r.path}`, parent, kind: "endpoint", group: "service", label: `${r.method} ${r.path}`,
        summary: r.method === "PAGE" ? "Page route." : "HTTP endpoint.", evidence: [{ path: r.file, lines: lines(r.line) }],
      });
      for (const [seg, rs] of groups) {
        if (grouped && rs.length > 1) {
          const gid = `rg:${pid}:${seg}`;
          nodes.push({
            id: gid, parent: pid, kind: "endpoint", group: "service", label: seg === "/" ? "/ (root)" : `/${seg} (${rs.length} routes)`,
            summary: `${rs.length} routes under /${seg === "/" ? "" : seg}.`, evidence: [rs[0].file ? { path: rs[0].file, lines: lines(rs[0].line) } : { path: pid }],
          });
          for (const r of rs) nodes.push(routeNode(r, gid));
        } else for (const r of rs) nodes.push(routeNode(r, pid));
      }
    }
    for (const [pid, files] of entryByPkg) {
      for (const f of files.slice(0, 5)) {
        nodes.push({ id: `entry:${f}`, parent: pid, kind: "file", group: "service", label: baseOf(f) === "index.ts" || baseOf(f) === "main.py" ? f : baseOf(f), summary: "Entrypoint.", evidence: [{ path: f, lines: "1" }] });
      }
    }
    void dirOf;
    return { nodes, edges };
  },
};
