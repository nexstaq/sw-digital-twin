/** What a question resolves to. The canvas renders this; it never prints an essay. */
export interface Highlight {
  title: string;
  detail?: string;
  /** set: light these up. impact: `focusId` fails and `ids` are what it takes down. info: one node, with a fact. */
  mode: "set" | "impact" | "info";
  ids: string[];
  focusId?: string;
  /** zoom path that shows the result */
  path: string[];
  source: "rules" | "ai";
}

export type AskResult = { ok: true; highlight: Highlight } | { ok: false; message: string; /** nothing matched; an AI fallback may help */ unrecognised?: boolean };
