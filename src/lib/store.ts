import { create } from "zustand";

import type { Highlight } from "@/lib/ask/types";

export type Lens = "overview" | "flow" | "ops" | "risk" | "tour";

interface TwinState {
  path: string[];
  selectedId: string | null;
  lens: Lens;
  /** hours ago; 0 = live */
  scrub: number;
  tourStep: number;
  tourPlaying: boolean;
  /** result of a ⌘K question, rendered on the canvas */
  highlight: Highlight | null;
  paletteOpen: boolean;
  /** incident replay in progress */
  replay: { playing: boolean; speed: 1 | 2 | 4 } | null;
  setReplay: (r: TwinState["replay"]) => void;
  setHighlight: (h: Highlight | null) => void;
  setPalette: (open: boolean) => void;
  setPath: (path: string[]) => void;
  drill: (id: string) => void;
  upTo: (depth: number) => void;
  select: (id: string | null) => void;
  setLens: (l: Lens) => void;
  setScrub: (h: number) => void;
  setTour: (step: number, playing?: boolean) => void;
}

export const useTwin = create<TwinState>((set) => ({
  path: [],
  selectedId: null,
  lens: "ops",
  scrub: 0,
  tourStep: 0,
  tourPlaying: true,
  highlight: null,
  paletteOpen: false,
  replay: null,
  setReplay: (replay) => set({ replay }),
  setHighlight: (highlight) => set({ highlight }),
  setPalette: (paletteOpen) => set({ paletteOpen }),
  setPath: (path) => set({ path, selectedId: null }),
  drill: (id) => set((s) => (s.path.at(-1) === id ? s : { path: [...s.path, id], selectedId: null })),
  upTo: (depth) => set((s) => ({ path: s.path.slice(0, depth), selectedId: null })),
  select: (id) => set({ selectedId: id }),
  setLens: (lens) => set({ lens }),
  setScrub: (scrub) => set({ scrub }),
  setTour: (tourStep, playing) => set((s) => ({ tourStep, tourPlaying: playing ?? s.tourPlaying })),
}));
