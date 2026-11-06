import type { TwinGraph } from "@/lib/graph/types";
import type { Verdict } from "@/lib/graph/verdict";

const esc = (s: unknown) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

type Tone = "nominal" | "degraded" | "failing" | "unknown";
// a glyph per state, so colour is never the only signal
const GLYPH: Record<Tone, string> = { nominal: "✓", degraded: "!", failing: "✕", unknown: "?" };
const COLOR: Record<Tone, string> = { nominal: "#34d399", degraded: "#fbbf24", failing: "#fb4b5c", unknown: "#7c8aa5" };
const STATE_WORD: Record<Tone, string> = { nominal: "healthy", degraded: "degraded", failing: "failing", unknown: "no signal" };
const MAX_BLOCKS = 8;

const PAGE_CSS = `*{box-sizing:border-box}html,body{margin:0}body{font:13px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;background:#0b1018;color:#e6edf7;padding:14px}
.card{border:1px solid #1e2a3d;border-radius:12px;background:#111826;padding:14px;max-width:560px}
.top{display:flex;align-items:center;gap:12px}.word{font-size:22px;font-weight:700;letter-spacing:.02em;display:flex;align-items:center;gap:8px}
.dot{display:inline-grid;place-items:center;width:26px;height:26px;border-radius:50%;border:2px solid currentColor;font-size:15px}
.repo{color:#8b9bb4;font-family:ui-monospace,Menlo,monospace;font-size:12px}.why{margin:8px 0 0;color:#c4cfe0}
ul{list-style:none;margin:12px 0 0;padding:0;display:flex;flex-wrap:wrap;gap:6px}
li{border:1px solid #1e2a3d;border-radius:999px;padding:2px 9px 2px 7px;font-size:12px;color:#c4cfe0;display:inline-flex;gap:6px;align-items:center}
li b{font-weight:700}.foot{margin-top:12px;font-size:12px;color:#8b9bb4;display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap}
a{color:#5eb3ff;text-decoration:none}a:hover,a:focus{text-decoration:underline}`;

/** The shell every embed answer shares, including "unavailable". No scripts, no external resources. */
const shell = (title: string, body: string) =>
  `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><meta name="referrer" content="no-referrer"><title>${esc(title)}</title><style>${PAGE_CSS}</style></head><body>${body}</body></html>`;

/** What anyone sees when the repo is private, unmapped, or the link is wrong. Identical for all of them, so the embed cannot probe for repos. */
export const renderEmbedUnavailable = (label: string) =>
  shell("Mission Control", `<div class="card" role="status"><div class="word" style="color:${COLOR.unknown}"><span class="dot" aria-hidden="true">?</span>${esc(label)}</div></div>`);

/**
 * A small read-only status card for an iframe: the launch verdict, why, and the top-level blocks with their state. Pure HTML with no
 * script, so a hostile label in the graph can only ever be text. `openUrl` is the page the "Open the full map" link goes to.
 */
export function renderEmbed(o: { repo: string; verdict: Verdict; graph: TwinGraph; openUrl: string }): string {
  const tone = o.verdict.tone as Tone;
  const blocks = o.graph.nodes.filter((n) => !n.parentId);
  const shown = blocks.slice(0, MAX_BLOCKS);
  const chips = shown.map((n) => {
    const t = n.state as Tone;
    return `<li><b style="color:${COLOR[t]}" aria-hidden="true">${GLYPH[t]}</b><span>${esc(n.label)}<span class="sr" style="position:absolute;left:-9999px"> ${STATE_WORD[t]}</span></span></li>`;
  }).join("");
  const more = blocks.length > shown.length ? `<li>+${blocks.length - shown.length} more</li>` : "";
  const body = `<div class="card" role="region" aria-label="Launch status for ${esc(o.repo)}">
<div class="top"><div class="word" style="color:${COLOR[tone]}"><span class="dot" aria-hidden="true">${GLYPH[tone]}</span><span>${esc(o.verdict.word)}</span></div><span class="repo">${esc(o.repo)}</span></div>
<p class="why">${esc(o.verdict.why)}</p>
${chips ? `<ul aria-label="Parts of the system">${chips}${more}</ul>` : ""}
<div class="foot"><span>${o.verdict.coverage.known} of ${o.verdict.coverage.total} parts report a signal</span><a href="${esc(o.openUrl)}" target="_top" rel="noopener noreferrer">Open the full map</a></div>
</div>`;
  return shell(`${o.repo}: ${o.verdict.word}`, body);
}

/** The ready-to-paste snippet. The URL is quoted by attribute, so a secret can never end the attribute. */
export const embedSnippet = (src: string) => `<iframe src="${esc(src)}" title="Mission Control launch status" width="560" height="260" style="border:0" loading="lazy" referrerpolicy="no-referrer"></iframe>`;
