import type { TwinGraph } from "./types";

/** Zoom path <-> URL (`?z=pay,pay-svc`). Invalid or non-contiguous ids are dropped. */
export function parsePath(search: string, graph: TwinGraph): string[] {
  const raw = new URLSearchParams(search).get("z");
  if (!raw) return [];
  const path: string[] = [];
  let parent: string | undefined;
  for (const id of raw.split(",")) {
    const node = graph.nodes.find((n) => n.id === id);
    if (!node || node.parentId !== parent) break;
    path.push(id);
    parent = id;
  }
  return path;
}

export function pathSearch(path: string[], current = ""): string {
  const params = new URLSearchParams(current);
  if (path.length) params.set("z", path.join(","));
  else params.delete("z");
  const s = params.toString();
  return s ? `?${s}` : "";
}
