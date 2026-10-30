"use client";

import { useCallback, useEffect, useState } from "react";
import { setOverride, type Override, type Overrides } from "@/lib/graph/overrides";

/** Human corrections for one repo. `canEdit` is true only when GitHub says the signed-in user can push. */
export function useOverrides(repo: string) {
  const [overrides, setOverrides] = useState<Overrides>({});
  const [canEdit, setCanEdit] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    fetch(`/api/overrides?repo=${encodeURIComponent(repo)}`, { cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((d: { overrides: Overrides; canEdit: boolean } | null) => { if (live && d) { setOverrides(d.overrides); setCanEdit(d.canEdit); } })
      .catch(() => {});
    return () => { live = false; };
  }, [repo]);

  const edit = useCallback(async (id: string, o: Override) => {
    const prev = overrides;
    const next = setOverride(prev, id, o);
    setOverrides(next); setError(null); // show it at once, undo if the server says no
    try {
      const r = await fetch(`/api/overrides?repo=${encodeURIComponent(repo)}`, { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ overrides: next }) });
      if (!r.ok) throw new Error(((await r.json().catch(() => null)) as { error?: string } | null)?.error ?? "Could not save.");
    } catch (e) {
      setOverrides(prev);
      setError(e instanceof Error ? e.message : "Could not save.");
    }
  }, [overrides, repo]);

  return { overrides, canEdit, edit, error };
}
