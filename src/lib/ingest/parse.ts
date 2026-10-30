import path from "node:path";
import Parser from "web-tree-sitter";

export type Lang = "typescript" | "tsx" | "javascript" | "python";

export function langFor(file: string): Lang | null {
  const ext = file.slice(file.lastIndexOf(".") + 1).toLowerCase();
  if (ext === "ts" || ext === "mts" || ext === "cts") return "typescript";
  if (ext === "tsx" || ext === "jsx") return "tsx";
  if (ext === "js" || ext === "mjs" || ext === "cjs") return "javascript";
  if (ext === "py") return "python";
  return null;
}

let ready: Promise<Record<Lang, Parser.Language>> | null = null;
const wasmDir = () => path.join(process.cwd(), "node_modules", "tree-sitter-wasms", "out");

/** Loads the WASM grammars once per process. */
function languages() {
  ready ??= (async () => {
    await Parser.init({ locateFile: (f: string) => path.join(process.cwd(), "node_modules", "web-tree-sitter", f) });
    const load = (n: string) => Parser.Language.load(path.join(wasmDir(), `tree-sitter-${n}.wasm`));
    const [typescript, tsx, javascript, python] = await Promise.all([load("typescript"), load("tsx"), load("javascript"), load("python")]);
    return { typescript, tsx, javascript, python };
  })();
  return ready;
}

export async function createParsers() {
  const langs = await languages();
  const cache = new Map<Lang, Parser>();
  return {
    parse(lang: Lang, source: string): Parser.Tree {
      let p = cache.get(lang);
      if (!p) { p = new Parser(); p.setLanguage(langs[lang]); cache.set(lang, p); }
      return p.parse(source);
    },
  };
}

export type { Parser };
