// Zips extension/dist for the Chrome Web Store / Edge Add-ons upload. Uses the system `zip` (macOS, Linux, CI runners).
import { execFileSync } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(here, "dist");
const zip = path.join(here, "mission-control-extension.zip");
if (!existsSync(path.join(dist, "manifest.json"))) throw new Error("Run `npm run ext:build` first.");
rmSync(zip, { force: true });
execFileSync("zip", ["-r", "-q", zip, "."], { cwd: dist });
console.log(`packed -> ${path.relative(process.cwd(), zip)}`);
