"use client";

import "@xyflow/react/dist/style.css";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Background, BackgroundVariant, Controls, ReactFlow, ReactFlowProvider, useReactFlow } from "@xyflow/react";
import ELK from "elkjs/lib/elk.bundled.js";
import { ChevronRight, Home, Search, Zap } from "lucide-react";
import type { TwinGraph, TwinNode } from "@/lib/graph/types";
import { childrenOf, nodeById } from "@/lib/graph/fixture";
import { blastRadius } from "@/lib/graph/blast";
import { parsePath, pathSearch } from "@/lib/graph/path";
import { displayName } from "@/lib/graph/display";
import { dimmedIds, tileSubtitle } from "@/lib/graph/lens";
import { ancestry } from "@/lib/graph/nav";
import { useTwin } from "@/lib/store";
import { AnimatedEdge, useReducedMotion, type FlowEdge } from "./AnimatedEdge";
import type { ReactNode } from "react";
import type { Incident } from "@/lib/health/incident";
import { toDigest } from "@/lib/ask/digest";
import { CommandPalette } from "./CommandPalette";
import { GoNoGoBanner } from "./GoNoGoBanner";
import { HighlightBar } from "./HighlightBar";
import { ReplayBar } from "./ReplayBar";
import { LensSwitcher } from "./LensSwitcher";
import { SideDrawer } from "./SideDrawer";
import { VocabContext } from "./status";
import { TILE_H, TILE_W, TileNodeComponent, type TileNode } from "./NodeTile";
import { TimelineScrubber } from "./TimelineScrubber";
import { TourPlayer, useTourSteps } from "./TourPlayer";

const nodeTypes = { tile: TileNodeComponent };
const edgeTypes = { flow: AnimatedEdge };
const elk = new ELK();
/** zooming in past this over a node with children opens it */
const AUTO_DRILL_ZOOM = 1.5;

interface ViewProps { /** "security" recolours the same map by risk: own headline, no lens switcher or deploy timeline */ mode?: "health" | "security"; /** replaces the GO / NO-GO banner */ banner?: ReactNode; incident?: Incident | null; anchor?: number; headerExtra?: ReactNode; /** drawer section for editing the selected node (people with push access) */ nodeEditor?: (node: TwinNode) => ReactNode }

function Inner({ graph, incident, anchor, headerExtra, nodeEditor, mode = "health", banner }: { graph: TwinGraph } & ViewProps) {
  const { path, selectedId, lens, drill, upTo, select, setPath, setLens, tourStep, highlight, setHighlight, setPalette, replay, setReplay, setScrub } = useTwin();
  const story = useTourSteps(graph);
  const touring = lens === "tour";
  const tourNodeId = touring ? story.tour[Math.min(tourStep, story.tour.length - 1)]?.nodeId : undefined;
  const rf = useReactFlow();
  const reduced = useReducedMotion();
  const wrapRef = useRef<HTMLDivElement>(null);
  const [hoverId, setHoverId] = useState<string | null>(null);
  const hydrating = useRef(true);
  const opening = useRef(false);
  const pointer = useRef<{ x: number; y: number } | null>(null);
  // live health swaps `graph` for a new object every few seconds; structure-only effects read it through this ref
  const graphRef = useRef(graph);
  useEffect(() => { graphRef.current = graph; });

  // --- URL <-> zoom path (shareable views, browser back/forward) ---
  useEffect(() => {
    setPath(parsePath(window.location.search, graphRef.current));
    hydrating.current = true;
    const onPop = () => setPath(parsePath(window.location.search, graphRef.current));
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, [graph.repo, graph.nodes.length, setPath]);

  useEffect(() => {
    if (hydrating.current) { hydrating.current = false; return; } // first pass: URL is the source of truth
    const next = pathSearch(path, window.location.search);
    if (next !== window.location.search) {
      window.history.pushState(null, "", `${window.location.pathname}${next}`);
    }
  }, [path]);

  // zoom into a node, then swap the view to its children
  const open = useCallback((id: string) => {
    if (opening.current) return; // wheel/dblclick can fire several times mid-animation
    if (reduced) return drill(id);
    opening.current = true;
    rf.fitView({ nodes: [{ id }], padding: 1.6, maxZoom: 1.7, duration: 320 });
    setTimeout(() => { drill(id); opening.current = false; }, 300);
  }, [rf, drill, reduced]);

  // entering the tour starts from the top level; each step flies to its node
  useEffect(() => { if (touring && useTwin.getState().path.length) upTo(0); }, [touring, upTo]);

  // Esc: deselect, then go up a level
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      const { selectedId: sel, path: pth, highlight: hl } = useTwin.getState();
      if (useTwin.getState().replay) { setReplay(null); setHighlight(null); setScrub(0); }
      else if (hl) setHighlight(null);
      else if (sel) select(null);
      else if (pth.length) upTo(pth.length - 1);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [select, upTo, setHighlight, setReplay, setScrub]);
  // a ⌘K answer takes the canvas to where the answer lives
  useEffect(() => {
    if (!highlight) return;
    setPath(highlight.path);
    if (highlight.mode === "info" && highlight.focusId) useTwin.getState().select(highlight.focusId);
  }, [highlight, setPath]);
  // everything that should stay bright: the answer and the blocks that contain it
  const lit = useMemo(() => {
    if (!highlight) return null;
    const ids = new Set<string>();
    for (const id of [...highlight.ids, ...(highlight.focusId ? [highlight.focusId] : [])]) { ids.add(id); for (const a of ancestry(graph, id)) ids.add(a); }
    return ids;
  }, [highlight, graph]);

  const parentId = path.at(-1) ?? null;
  const visible = useMemo(
    () => childrenOf(graph, parentId).sort((a, b) => (a.narrative?.order ?? 99) - (b.narrative?.order ?? 99)),
    [graph, parentId],
  );
  const [laid, setLaid] = useState<{ nodes: TileNode[]; edges: FlowEdge[] }>({ nodes: [], edges: [] });
  const layoutKey = useMemo(() => {
    const ids = new Set(visible.map((v) => v.id));
    return `${visible.map((v) => v.id).join("|")}#${graph.edges.filter((x) => ids.has(x.from) && ids.has(x.to)).map((x) => x.id).join("|")}`;
  }, [visible, graph.edges]);

  useEffect(() => {
    let cancelled = false;
    const graph = graphRef.current;
    const visible = childrenOf(graph, parentId).sort((a, b) => (a.narrative?.order ?? 99) - (b.narrative?.order ?? 99));
    const ids = new Set(visible.map((v) => v.id));
    const es = graph.edges.filter((x) => ids.has(x.from) && ids.has(x.to));
    elk
      .layout({
        id: "root",
        layoutOptions: {
          "elk.algorithm": "layered",
          "elk.direction": "RIGHT",
          "elk.spacing.nodeNode": "44",
          "elk.layered.spacing.nodeNodeBetweenLayers": "64",
          "elk.layered.nodePlacement.strategy": "NETWORK_SIMPLEX",
          "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES", // honours the flow order hint
        },
        children: visible.map((v) => ({ id: v.id, width: TILE_W, height: TILE_H })),
        edges: es.map((x) => ({ id: x.id, sources: [x.from], targets: [x.to] })),
      })
      .then((res) => {
        if (cancelled) return;
        setLaid({
          nodes: visible.map((v) => {
            const p = res.children?.find((c) => c.id === v.id);
            return {
              id: v.id, type: "tile", position: { x: p?.x ?? 0, y: p?.y ?? 0 },
              // known size => xyflow never hides the node while re-measuring after a data change
              width: TILE_W, height: TILE_H,
              data: { node: v, childCount: childrenOf(graph, v.id).length, dim: false, impacted: false, title: v.label },
            };
          }),
          edges: es.map((x) => ({
            id: x.id, source: x.from, target: x.to, type: "flow",
            data: { throughput: x.throughput, errorRate: x.errorRate },
          })),
        });
        requestAnimationFrame(() => rf.fitView({ padding: 0.12, minZoom: 0.6, duration: reduced ? 0 : 500 }));
      });
    return () => { cancelled = true; };
  }, [layoutKey, parentId, rf, reduced]);

  useEffect(() => {
    if (!touring || !tourNodeId || !laid.nodes.some((n) => n.id === tourNodeId)) return;
    rf.fitView({ nodes: [{ id: tourNodeId }], padding: 1.6, maxZoom: 1.25, duration: reduced ? 0 : 800 });
  }, [touring, tourNodeId, laid.nodes, rf, reduced]);

  useEffect(() => {
    if (!lit) return;
    const hit = laid.nodes.filter((n) => lit.has(n.id));
    if (hit.length) rf.fitView({ nodes: hit, padding: 0.5, maxZoom: 1.2, duration: reduced ? 0 : 600 });
  }, [lit, laid.nodes, rf, reduced]);

  // hovering a node shows what breaks if it fails
  const impact = useMemo(
    () => (hoverId ? blastRadius(laid.edges.map((e) => ({ id: e.id, from: e.source, to: e.target, kind: graph.edges.find((g) => g.id === e.id)!.kind, throughput: 0, errorRate: 0 })), hoverId) : null),
    [hoverId, laid.edges, graph.edges],
  );

  // lens: Ops spotlights anything that needs attention
  const lensDim = useMemo(() => dimmedIds(laid.nodes.map((n) => nodeById(graph, n.id) ?? n.data.node), lens), [laid.nodes, graph, lens]);
  const nodes = useMemo(
    () => laid.nodes.map((nd0) => {
      const fresh = nodeById(graph, nd0.id) ?? nd0.data.node;
      const nd = { ...nd0, data: { ...nd0.data, node: fresh, childCount: childrenOf(graph, nd0.id).length } };
      const inBlast = impact ? nd.id === hoverId || impact.nodes.has(nd.id) : true;
      return {
        ...nd, selected: nd.id === selectedId || nd.id === highlight?.focusId,
        data: {
          ...nd.data,
          title: displayName(nd.data.node, lens),
          subtitle: tileSubtitle(nd.data.node, lens),
          dim: touring ? nd.id !== tourNodeId : lit ? !lit.has(nd.id) : impact ? !inBlast : lensDim.has(nd.id),
          impacted: highlight?.mode === "impact" ? highlight.ids.includes(nd.id) : !!impact && impact.nodes.has(nd.id),
        },
      };
    }),
    [laid.nodes, graph, selectedId, lens, lensDim, lit, highlight, impact, hoverId, touring, tourNodeId],
  );
  const edges = useMemo(
    () => laid.edges.map((e) => {
      const fresh = graph.edges.find((g) => g.id === e.id);
      return { ...e, data: { ...e.data!, throughput: fresh?.throughput ?? e.data!.throughput, errorRate: fresh?.errorRate ?? e.data!.errorRate, faded: !!impact && !impact.edges.has(e.id) } };
    }),
    [laid.edges, graph.edges, impact],
  );
  const hovered = hoverId ? nodeById(graph, hoverId) : null;

  const selected = selectedId ? nodeById(graph, selectedId) ?? null : null;
  const crumbs = path.map((id) => nodeById(graph, id)!);

  return (
    <div className="flex h-dvh flex-col">
      <header className="relative z-30 flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-line bg-surface/80 px-4 py-2.5 backdrop-blur">
        <div className="flex items-center gap-2.5">
          <div className="grid h-7 w-7 place-items-center rounded-lg bg-accent/15 text-accent">◎</div>
          <div className="leading-tight">
            <div className="text-sm font-semibold">Mission Control</div>
            <div className="font-mono text-[11px] text-ink-dim">{graph.repo}</div>
          </div>
        </div>
        {mode === "security" ? banner : <GoNoGoBanner graph={graph} onShow={(b) => { setHighlight(null); setPath(b.path); select(b.id); }} />}
        <div className="ml-auto flex items-center gap-2">
          {headerExtra}
          <button onClick={() => setPalette(true)} aria-label="Ask or jump (Command K)" className="flex items-center gap-2 rounded-lg border border-line bg-surface px-2.5 py-1.5 text-[13px] text-ink-dim hover:text-ink">
            <Search size={14} aria-hidden /><span className="hidden lg:inline">Ask or jump</span><kbd className="hidden rounded border border-line px-1 font-mono text-[10px] text-ink-faint lg:inline">⌘K</kbd>
          </button>
          {mode === "health" && <LensSwitcher />}
        </div>
      </header>

      <nav aria-label="Mission path" className="flex items-center gap-1 px-4 py-2 text-[13px] text-ink-dim">
        <button onClick={() => upTo(0)} className="flex items-center gap-1 rounded px-1.5 py-0.5 hover:bg-raised hover:text-ink">
          <Home size={13} /> System
        </button>
        {crumbs.map((c, i) => (
          <span key={c.id} className="flex items-center gap-1">
            <ChevronRight size={13} className="text-ink-faint" />
            <button onClick={() => upTo(i + 1)} className="rounded px-1.5 py-0.5 hover:bg-raised hover:text-ink">{c.label}</button>
          </span>
        ))}
      </nav>

      <div ref={wrapRef} className="relative flex-1" onPointerMove={(e) => { pointer.current = { x: e.clientX, y: e.clientY }; }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          edgeTypes={edgeTypes}
          colorMode="dark"
          minZoom={0.3}
          maxZoom={1.8}
          zoomOnDoubleClick={false}
          nodesDraggable={false}
          nodesConnectable={false}
          onNodeClick={(_, nd) => { select(nd.id); }}
          onNodeDoubleClick={(_, nd) => childrenOf(graph, nd.id).length && open(nd.id)}
          onNodeMouseEnter={(_, nd) => setHoverId(nd.id)}
          onNodeMouseLeave={() => setHoverId(null)}
          onMoveEnd={(event, vp) => {
            // user-initiated zoom only (programmatic fitView passes no event)
            if (!event || vp.zoom < AUTO_DRILL_ZOOM || !wrapRef.current) return;
            // wheel-zoom is anchored on the cursor, so that is the node the user is diving into
            const r = wrapRef.current.getBoundingClientRect();
            const at = pointer.current ?? { x: r.left + r.width / 2, y: r.top + r.height / 2 };
            const c = rf.screenToFlowPosition(at);
            const hit = laid.nodes.find((n) =>
              c.x >= n.position.x && c.x <= n.position.x + TILE_W && c.y >= n.position.y && c.y <= n.position.y + TILE_H);
            if (hit && hit.data.childCount > 0) open(hit.id);
          }}
          onPaneClick={() => { select(null); }}
          proOptions={{ hideAttribution: false }}
        >
          <Background variant={BackgroundVariant.Dots} gap={28} size={1.2} color="#1a2638" />
          <Controls showInteractive={false} position="bottom-left" />
        </ReactFlow>
        <SideDrawer
          node={touring ? null : selected}
          lens={lens}
          childCount={selected ? childrenOf(graph, selected.id).length : 0}
          editor={selected && nodeEditor ? nodeEditor(selected) : undefined}
          onClose={() => select(null)}
          onDrill={() => selected && open(selected.id)}
          onAsk={async (nodeId, question) => {
            const res = await fetch("/api/ask", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ mode: "explain", nodeId, question, digest: toDigest(graph) }) });
            return (await res.json()) as { ok: true; text: string } | { ok: false; message: string };
          }}
        />
        {touring && <TourPlayer graph={graph} onExit={() => setLens("overview")} />}
        {replay && incident && anchor ? <ReplayBar graph={graph} incident={incident} anchor={anchor} /> : <HighlightBar graph={graph} />}
        <p className={`pointer-events-none absolute bottom-3 left-1/2 -translate-x-1/2 text-xs text-ink-faint ${touring || highlight || replay ? "hidden" : ""}`}>
          {hovered && impact ? (
            <span className="flex items-center gap-1.5 rounded-full border border-failing/40 bg-surface/90 px-3 py-1 text-ink-dim">
              <Zap size={12} className="text-failing" aria-hidden />
              If {hovered.label} fails:{" "}
              <span className="text-ink">
                {impact.nodes.size ? [...impact.nodes].map((id) => nodeById(graph, id)?.label).join(", ") : "nothing else is affected"}
              </span>
            </span>
          ) : (
            "Click for details · double-click or zoom in to open · Esc to go back"
          )}
        </p>
      </div>

      {mode === "health" && <TimelineScrubber deploys={graph.deploys} activity={graph.activity} incident={incident} anchor={anchor} />}
      <CommandPalette graph={graph} />
    </div>
  );
}

export function Canvas({ graph, ...view }: { graph: TwinGraph } & ViewProps) {
  return (
    <VocabContext.Provider value={view.mode === "security" ? "security" : "health"}>
      <ReactFlowProvider>
        <Inner graph={graph} {...view} />
      </ReactFlowProvider>
    </VocabContext.Provider>
  );
}
