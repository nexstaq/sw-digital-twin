"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import type { ConnectorStatus, Target } from "@/lib/connectors/types";
import { proposeMappings, type Proposal } from "@/lib/connectors/match";
import type { TwinGraph } from "@/lib/graph/types";

const key = (repo: string) => `twin:mappings:${repo.toLowerCase()}`;
const read = (repo: string): Record<string, string> => { try { return JSON.parse(localStorage.getItem(key(repo)) ?? "{}") as Record<string, string>; } catch { return {}; } };

const putShared = (repo: string, m: Record<string, string>) =>
  fetch(`/api/mappings?repo=${encodeURIComponent(repo)}`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ mappings: m }) }).catch(() => undefined);

/**
 * Confirmed signal -> node mappings. When you have write access to the repo they are saved on the server and shared with
 * everyone who can see it; otherwise they are kept in this browser only. "Confirm once" survives reloads either way.
 */
export function useMappings(repo: string) {
  const [mappings, setMappings] = useState<Record<string, string>>({});
  const [canEdit, setCanEdit] = useState<boolean | null>(null);
  useEffect(() => {
    let live = true;
    setMappings(read(repo)); // eslint-disable-line react-hooks/set-state-in-effect
    fetch(`/api/mappings?repo=${encodeURIComponent(repo)}`, { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((d: { mappings: Record<string, string>; canEdit: boolean } | null) => { if (live && d) { setMappings((m) => ({ ...d.mappings, ...m })); setCanEdit(d.canEdit); } })
      .catch(() => {});
    return () => { live = false; };
  }, [repo]);

  const commit = useCallback((next: Record<string, string>) => {
    try { localStorage.setItem(key(repo), JSON.stringify(next)); } catch { /* private mode: lasts for this session */ }
    if (canEdit) void putShared(repo, next);
  }, [repo, canEdit]);

  const confirm = useCallback((entries: Record<string, string>) => {
    setMappings((m) => { const next = { ...m, ...entries }; commit(next); return next; });
  }, [commit]);
  const forget = useCallback((id: string) => {
    setMappings((m) => { const { [id]: _drop, ...rest } = m; commit(rest); return rest; }); // eslint-disable-line @typescript-eslint/no-unused-vars
  }, [commit]);
  return { mappings, confirm, forget, shared: canEdit };
}

export function useConnectors(repo: string, graph: TwinGraph, mappings: Record<string, string>, enabled: boolean) {
  const [data, setData] = useState<{ status: ConnectorStatus[]; targets: Target[] } | null>(null);
  useEffect(() => {
    if (!enabled) return;
    let live = true;
    fetch(`/api/connectors?repo=${encodeURIComponent(repo)}`).then((r) => r.json()).then((d) => { if (live && d.status) setData(d); }).catch(() => {});
    return () => { live = false; };
  }, [repo, enabled]);
  const proposals: Proposal[] = useMemo(() => (data ? proposeMappings(graph, data.targets, mappings) : []), [data, graph, mappings]);
  return { status: data?.status ?? [], proposals };
}
