// Bundles the extension into extension/dist. TWIN_ORIGIN picks which Mission Control it talks to (default: production).
//   node extension/build.mjs                              -> production
//   TWIN_ORIGIN=http://localhost:3300 node extension/build.mjs --out=extension/dist-e2e
import { build } from "esbuild";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const origin = (process.env.TWIN_ORIGIN ?? "https://sw-digital-twin.nexstaq.com").replace(/\/$/, "");
if (!/^https?:\/\/[\w.-]+(:\d+)?$/.test(origin)) throw new Error(`TWIN_ORIGIN must be an origin like https://host, got ${origin}`);
const outArg = process.argv.find((a) => a.startsWith("--out="))?.slice(6);
const out = path.resolve(outArg ?? path.join(here, "dist"));

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
await build({
  entryPoints: { content: path.join(here, "src/content.ts"), background: path.join(here, "src/background.ts") },
  outdir: out, bundle: true, minify: true, target: "chrome120", format: "iife", legalComments: "none",
  define: { TWIN_ORIGIN: JSON.stringify(origin) },
});
writeFileSync(path.join(out, "manifest.json"), readFileSync(path.join(here, "manifest.json"), "utf8").replaceAll("__TWIN_ORIGIN__", origin));
if (existsSync(path.join(here, "icons"))) cpSync(path.join(here, "icons"), path.join(out, "icons"), { recursive: true });
console.log(`extension built -> ${path.relative(process.cwd(), out)} (talks to ${origin})`);
