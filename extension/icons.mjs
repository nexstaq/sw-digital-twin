// Renders extension/icons/{16,48,128}.png from one SVG using Playwright's Chromium. Run once, commit the PNGs.
import { chromium } from "@playwright/test";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const out = path.join(path.dirname(fileURLToPath(import.meta.url)), "icons");
mkdirSync(out, { recursive: true });
const svg = (n) => `<svg xmlns="http://www.w3.org/2000/svg" width="${n}" height="${n}" viewBox="0 0 128 128">
  <rect width="128" height="128" rx="28" fill="#0b1220"/>
  <circle cx="64" cy="64" r="34" fill="none" stroke="#38bdf8" stroke-width="12"/>
  <circle cx="64" cy="64" r="10" fill="#38bdf8"/>
  <circle cx="98" cy="30" r="10" fill="#22c55e"/>
</svg>`;
const b = await chromium.launch();
for (const n of [16, 48, 128]) {
  const p = await b.newPage({ viewport: { width: n, height: n } });
  await p.setContent(`<body style="margin:0;background:transparent">${svg(n)}</body>`);
  await p.screenshot({ path: path.join(out, `${n}.png`), omitBackground: true });
  await p.close();
}
await b.close();
console.log("icons written to", path.relative(process.cwd(), out));
