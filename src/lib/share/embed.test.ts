import { describe, expect, it } from "vitest";
import { fixtureGraph } from "@/lib/graph/fixture";
import { explainVerdict } from "@/lib/graph/verdict";
import { securityHeaders } from "../security/headers";
import { embedSnippet, renderEmbed, renderEmbedUnavailable } from "./embed";

const graph = fixtureGraph;
const verdict = explainVerdict(graph);
const open = "https://twin.example/scan?repo=acme%2Fshop";

describe("renderEmbed", () => {
  it("names the verdict in words, lists the top-level parts, and links to the full map", () => {
    const h = renderEmbed({ repo: "acme/shop", verdict, graph, openUrl: open });
    expect(h).toContain(verdict.word);
    expect(h).toContain("acme/shop");
    for (const n of graph.nodes.filter((x) => !x.parentId).slice(0, 3)) expect(h).toContain(n.label.replace(/&/g, "&amp;"));
    expect(h).toContain(`href="${open}"`);
    expect(h).toContain('target="_top"');
  });
  it("runs no script and loads nothing from anywhere", () => {
    const h = renderEmbed({ repo: "acme/shop", verdict, graph, openUrl: open });
    expect(h).not.toMatch(/<script|<link|<img|<iframe|src=|\son[a-z]+=/i);
  });
  it("escapes hostile labels, the repo name and the link", () => {
    const evil = { ...graph, nodes: graph.nodes.map((n, i) => (i === 0 ? { ...n, parentId: undefined, label: '<img src=x onerror=alert(1)>"' } : n)) };
    const h = renderEmbed({ repo: "a/<b>", verdict: { ...verdict, why: "<script>1</script>" }, graph: evil, openUrl: 'https://x/"><script>' });
    expect(h).not.toContain("<script>");
    expect(h).not.toContain("<img src=x");
    expect(h).not.toContain('"><script>');
  });
  it("caps the list of parts", () => {
    const many = { ...graph, nodes: Array.from({ length: 20 }, (_, i) => ({ ...graph.nodes[0], id: `n${i}`, parentId: undefined, label: `part-${i}` })) };
    const h = renderEmbed({ repo: "a/b", verdict, graph: many, openUrl: open });
    expect(h).toContain("part-7");
    expect(h).not.toContain("part-8");
    expect(h).toContain("+12 more");
  });
  it("the unavailable card says nothing about why", () => {
    expect(renderEmbedUnavailable("Unavailable")).toContain("Unavailable");
  });
});

describe("embedSnippet", () => {
  it("quotes the URL so a secret can never end the attribute", () => {
    const s = embedSnippet('https://x/embed/a/b?t="onload="x');
    expect(s).toContain("&quot;onload=&quot;");
    expect(s).toMatch(/^<iframe src="[^"]*" title=/);
  });
});

describe("framable headers", () => {
  const h = securityHeaders(true, { framable: true });
  const get = (k: string) => h.find((x) => x.key === k)?.value;
  it("let any site frame the card, and nothing else may run in it", () => {
    expect(get("Content-Security-Policy")).toContain("frame-ancestors *");
    expect(get("Content-Security-Policy")).toContain("default-src 'none'");
    expect(get("Content-Security-Policy")).not.toMatch(/script-src/);
    expect(get("X-Frame-Options")).toBeUndefined();
  });
  it("every other page still cannot be framed", () => {
    const d = securityHeaders(true);
    expect(d.find((x) => x.key === "X-Frame-Options")!.value).toBe("DENY");
    expect(d.find((x) => x.key === "Content-Security-Policy")!.value).toContain("frame-ancestors 'none'");
  });
});
