"use client";

import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import {
  Boxes, Cloud, Database, FileCode2, Globe, Layers, ListOrdered, Package, Play, ChevronRight, type LucideIcon,
} from "lucide-react";
import type { NodeKind, TwinNode } from "@/lib/graph/types";
import { Sparkline, StatusRing, STATUS } from "./status";

const KIND_ICON: Record<NodeKind, LucideIcon> = {
  service: Boxes, job: Play, package: Package, datastore: Database, queue: ListOrdered,
  external: Cloud, endpoint: Globe, file: FileCode2, env: Layers,
};

export const TILE_W = 236;
export const TILE_H = 104;

interface ViewProps {
  node: TwinNode;
  childCount?: number;
  selected?: boolean;
  dim?: boolean;
  /** impacted by the hovered node failing */
  impacted?: boolean;
  /** name to show (friendly or technical depending on lens) */
  title?: string;
  /** line under the name, chosen by lens; defaults to the node kind */
  subtitle?: string;
}

/** Pure presentational tile, usable outside React Flow. */
export function NodeTileView({ node, childCount = 0, selected, dim, impacted, title, subtitle }: ViewProps) {
  const s = STATUS[node.state];
  const Icon = KIND_ICON[node.kind];
  return (
    <div
      className={`relative rounded-xl border bg-surface/95 px-3.5 py-3 backdrop-blur transition-[opacity,box-shadow,transform] duration-300 ${impacted ? "border-failing/80" : s.border} ${selected ? "scale-[1.03]" : ""}`}
      style={{
        width: TILE_W,
        height: TILE_H,
        opacity: dim ? 0.42 : 1,
        boxShadow: impacted ? "0 0 0 2px var(--color-failing), 0 0 28px -4px var(--color-failing)" : node.state === "nominal" || node.state === "unknown"
          ? selected ? `0 0 0 1.5px ${s.color}` : "none"
          : `0 0 ${selected ? 34 : 22}px -6px ${s.color}, 0 0 0 ${selected ? 1.5 : 0}px ${s.color}`,
      }}
    >
      <div className="flex items-start gap-2.5">
        <StatusRing status={node.state} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-[13.5px] font-semibold leading-tight text-ink">{title ?? node.label}</div>
          {subtitle ? (
            <div title={subtitle} className="mt-0.5 line-clamp-2 text-[11px] leading-snug text-ink-dim">{subtitle}</div>
          ) : (
            <div className="mt-0.5 flex items-center gap-1 text-[11px] text-ink-dim">
              <Icon size={11} aria-hidden />
              <span className="capitalize">{node.kind}</span>
            </div>
          )}
        </div>
      </div>
      <div className="absolute inset-x-3.5 bottom-2.5 flex items-end justify-between">
        <Sparkline values={node.spark} status={node.state} />
        {childCount > 0 ? (
          <span className="flex items-center gap-0.5 rounded-full bg-raised px-1.5 py-0.5 text-[10.5px] text-ink-dim">
            {childCount} <ChevronRight size={11} aria-hidden />
          </span>
        ) : (
          <span className="font-mono text-[11px] tabular-nums text-ink-faint">{Math.round(node.score * 100)}</span>
        )}
      </div>
    </div>
  );
}

export type TileNode = Node<{ node: TwinNode; childCount: number; dim: boolean; impacted: boolean; title: string; subtitle?: string }, "tile">;

export function TileNodeComponent({ data, selected }: NodeProps<TileNode>) {
  return (
    <div className="tile-in">
      <Handle type="target" position={Position.Left} className="!h-1.5 !w-1.5 !border-0 !bg-line" />
      <NodeTileView node={data.node} childCount={data.childCount} dim={data.dim} impacted={data.impacted} title={data.title} subtitle={data.subtitle} selected={selected} />
      <Handle type="source" position={Position.Right} className="!h-1.5 !w-1.5 !border-0 !bg-line" />
    </div>
  );
}
