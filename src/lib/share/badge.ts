export type BadgeTone = "nominal" | "degraded" | "failing" | "unknown";

// Solid fills with white text; the WORD carries the meaning too, so colour is never the only signal.
const FILL: Record<BadgeTone, string> = { nominal: "#1a7f37", degraded: "#9a6700", failing: "#cf222e", unknown: "#6e7781" };
const LABEL_FILL = "#24292f";

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
/** rough text width for 11px Verdana-ish; badges only need to be close, not exact */
const width = (s: string) => Math.round(s.length * 6.6 + 12);

export function renderBadge(label: string, value: string, tone: BadgeTone): string {
  const lw = width(label), vw = width(value), w = lw + vw;
  const title = `${label}: ${value}`;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${esc(title)}"><title>${esc(title)}</title>`
    + `<clipPath id="r"><rect width="${w}" height="20" rx="3"/></clipPath>`
    + `<g clip-path="url(#r)"><rect width="${lw}" height="20" fill="${LABEL_FILL}"/><rect x="${lw}" width="${vw}" height="20" fill="${FILL[tone]}"/></g>`
    + `<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">`
    + `<text x="${lw / 2}" y="14">${esc(label)}</text><text x="${lw + vw / 2}" y="14" font-weight="bold">${esc(value)}</text></g></svg>`;
}
