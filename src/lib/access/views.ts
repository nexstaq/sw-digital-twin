import { z } from "zod";

/**
 * Who may open a view of a repository. Two models today:
 *  - "github": anyone GitHub says can read the repo (anyone at all, for a public repo). The long-standing rule.
 *  - "maintainers": only people with push access, checked with their own GitHub token.
 * Adding a model (a named GitHub team, a list of people) means one more entry here and one more branch in `authorizeRepo`.
 */
export const MODELS = {
  github: { label: "Anyone who can read the repository on GitHub", short: "GitHub access", description: "Public repositories are open to everyone; private ones to people GitHub says can read them." },
  maintainers: { label: "Maintainers only", short: "Maintainers", description: "Only people with write (push) access to the repository, and they must sign in." },
} as const;
export type ModelId = keyof typeof MODELS;
export const MODEL_IDS = Object.keys(MODELS) as ModelId[];

export interface ViewDef { id: string; label: string; covers: string; default: ModelId; /** models a maintainer may pick; one entry means the view is fixed */ allowed: readonly ModelId[]; /** why a fixed view is fixed */ fixedBecause?: string }

const VIEW_LIST = [
  { id: "map", label: "System map", covers: "The map, its saved versions, corrections and signal mappings.", default: "github", allowed: ["github", "maintainers"] },
  { id: "health", label: "Live health", covers: "Health colouring, the launch verdict (GO / HOLD / NO-GO), the extension's status button and the live stream. Share links, which you create on purpose, still work.", default: "github", allowed: ["github", "maintainers"] },
  { id: "security", label: "Security", covers: "Findings, reports, live-site checks, imports and scheduled scans.", default: "maintainers", allowed: ["maintainers"], fixedBecause: "A list of a project's weaknesses is far more sensitive than its architecture, so it is never opened to everyone who can read the code." },
] as const satisfies readonly ViewDef[];
export type ViewId = (typeof VIEW_LIST)[number]["id"];
export const VIEWS: readonly (ViewDef & { id: ViewId })[] = VIEW_LIST;
export const VIEW_IDS = VIEWS.map((v) => v.id);

export const AccessSettingsSchema = z.record(z.enum(VIEW_IDS as [ViewId, ...ViewId[]]), z.enum(MODEL_IDS as [ModelId, ...ModelId[]]));
/** only what a maintainer changed; everything else is the view's default */
export type AccessSettings = Partial<Record<ViewId, ModelId>>;

const def = (view: ViewId): ViewDef => VIEWS.find((v) => v.id === view)!;

/** The model in force for a view. A stored value that is no longer allowed for that view is ignored, so settings can never weaken a fixed view. */
export function modelFor(settings: AccessSettings | null | undefined, view: ViewId): ModelId {
  const v = def(view);
  const chosen = settings?.[view];
  return chosen && v.allowed.includes(chosen) ? chosen : v.default;
}

/** True when this view needs push access. */
export const needsMaintainer = (settings: AccessSettings | null | undefined, view: ViewId): boolean => modelFor(settings, view) === "maintainers";

export function validChoice(view: string, model: string): { ok: true; view: ViewId; model: ModelId } | { ok: false; reason: string } {
  const v = VIEWS.find((x) => x.id === view);
  if (!v) return { ok: false, reason: "There is no such view." };
  if (!(model in MODELS)) return { ok: false, reason: "There is no such access model." };
  const m = model as ModelId;
  if (!(v.allowed as readonly ModelId[]).includes(m)) return { ok: false, reason: v.fixedBecause ?? `${v.label} cannot use that model.` };
  return { ok: true, view: v.id, model: m };
}
