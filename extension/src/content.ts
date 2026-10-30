import { repoFromPath } from "./repo";
import { viewOf, type Status } from "./status";

declare const TWIN_ORIGIN: string; // injected by build.mjs

const HOST_ID = "sw-twin-extension";
const CSS = `
:host { all: initial; }
a { display: inline-flex; align-items: center; gap: 6px; font: 500 12px/20px -apple-system, "Segoe UI", system-ui, sans-serif; padding: 3px 10px; border-radius: 6px; text-decoration: none; cursor: pointer;
  color: var(--fg, #1f2328); background: var(--bg, #f6f8fa); border: 1px solid var(--bd, #d1d9e0); }
a:hover { background: var(--bg-h, #eaeef2); }
a:focus-visible { outline: 2px solid #0969da; outline-offset: 2px; }
.ring { width: 12px; height: 12px; border-radius: 50%; border: 2px solid currentColor; box-sizing: border-box; }
.pill { font-weight: 700; padding: 0 7px; border-radius: 10px; color: #fff; letter-spacing: .02em; }
.nominal { background: #1a7f37; } .degraded { background: #9a6700; } .failing { background: #cf222e; } .unknown { background: #6e7781; }
.float { position: fixed; right: 16px; bottom: 16px; z-index: 2147483000; box-shadow: 0 4px 16px rgba(0,0,0,.25); }
@media (prefers-color-scheme: dark) { a { --fg: #f0f6fc; --bg: #212830; --bd: #3d444d; --bg-h: #2a313c; } }`;

let current: { repo: string; shadow: ShadowRoot; floating: boolean; status: Status | null } | null = null;

function place(host: HTMLElement): boolean {
  // GitHub's own button row, when it exists; otherwise a floating pill. GitHub changes this markup often, so never depend on it.
  const row = document.querySelector("ul.pagehead-actions");
  if (!row) return false;
  const li = document.createElement("li");
  li.append(host);
  row.prepend(li);
  return true;
}

function render(shadow: ShadowRoot, repo: string, status: Status | null, floating: boolean) {
  const v = viewOf(status, TWIN_ORIGIN, repo);
  shadow.replaceChildren();
  const style = document.createElement("style");
  style.textContent = CSS;
  const a = document.createElement("a");
  a.href = v.href;
  a.target = "_blank";
  a.rel = "noopener";
  a.title = v.title;
  a.setAttribute("aria-label", `View Twin. ${v.title}`);
  if (floating) a.className = "float";
  const ring = document.createElement("span");
  ring.className = "ring";
  ring.setAttribute("aria-hidden", "true");
  const label = document.createElement("span");
  label.textContent = "View Twin";
  const pill = document.createElement("span");
  pill.className = `pill ${v.tone}`;
  pill.textContent = `${v.glyph} ${v.text}`; // textContent only: nothing from the network is ever parsed as HTML
  a.append(ring, label, pill);
  shadow.append(style, a);
}

function mount(repo: string) {
  document.getElementById(HOST_ID)?.closest("li")?.remove();
  document.getElementById(HOST_ID)?.remove();
  const host = document.createElement("div");
  host.id = HOST_ID;
  const floating = !place(host);
  if (floating) document.documentElement.append(host);
  const shadow = host.attachShadow({ mode: "open" });
  current = { repo, shadow, floating, status: null };
  render(shadow, repo, null, floating);
  refresh();
}

function refresh() {
  const c = current;
  if (!c) return;
  chrome.runtime.sendMessage({ type: "status", repo: c.repo }).then((s: Status | undefined) => {
    if (current === c && s) { c.status = s; render(c.shadow, c.repo, s, c.floating); }
  }).catch(() => { /* worker asleep or extension reloaded: leave the button as it is */ });
}

function update() {
  const repo = repoFromPath(location.pathname);
  const present = !!document.getElementById(HOST_ID);
  if (!repo) { document.getElementById(HOST_ID)?.closest("li")?.remove(); document.getElementById(HOST_ID)?.remove(); current = null; return; }
  if (current?.repo === repo && present) return;
  mount(repo);
}

// GitHub navigates without reloading the page (Turbo), so re-check on its events, back/forward, and a slow safety net.
for (const ev of ["turbo:render", "turbo:load", "pjax:end", "popstate"]) document.addEventListener(ev, update);
window.addEventListener("popstate", update);
setInterval(update, 1500);
// Signed in (or mapped the repo) in another tab? Coming back should update the badge without a reload.
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "visible" && current && current.status?.state !== "ok") refresh(); });
update();
