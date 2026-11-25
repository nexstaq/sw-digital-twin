import { z } from "zod";
import { isIP } from "node:net";
import { ACTION_CLASSES, AGENTS, classRank, parseRoe, techniqueId, type ActionClass, type Agent, type Roe } from "./roe";

/**
 * The scope guard. Every tool call an agent makes passes through `allow()` before anything happens, and the answer is decided by
 * code, never by a prompt. It is a pure function: same inputs, same answer, no clock, no network, no mutation. Default deny:
 * anything it cannot positively match against the ROE is refused, and nothing it is given can make it throw.
 *
 * Order matters and is fixed: the ROE and the clock, then the kill switch, the window and the budgets, and only then the action.
 * So a stopped, expired or exhausted run is refused without ever interpreting what the agent asked for.
 */

/** The most harmful class each agent may ever use, whatever the ROE says. Raising one needs an ADR and a human approval gate. */
export const AGENT_CEILING: Record<Agent, ActionClass> = {
  whitebox: "exploit-range",
  graybox: "exploit-range",
  redteam: "exploit-range",
  blue: "observe",
  narrator: "observe",
};

/** Real targets (anything but the range) can only ever be observed or probed. */
const REAL_TARGET_CEILING: ActionClass = "probe";

export type DenyReason =
  | "roe-invalid" | "state-invalid" | "clock-invalid"
  | "killed" | "not-yet-valid" | "expired"
  | "budget-steps" | "budget-tokens" | "budget-time" | "budget-cost"
  | "action-invalid" | "agent-not-in-roe" | "class-above-agent-ceiling" | "class-not-in-roe" | "class-not-allowed-on-target"
  | "technique-missing" | "technique-forbidden" | "technique-not-allowed"
  | "target-not-in-roe" | "url-unsafe" | "host-mismatch" | "ownership-not-reproved";

export type Decision = { ok: true } | { ok: false; reason: DenyReason; detail: string };

const ident = z.string().regex(/^[A-Za-z0-9_-]{1,64}$/);
const ActionSchema = z.strictObject({
  id: ident,
  agent: z.enum(AGENTS),
  tool: z.string().regex(/^[a-z][a-z0-9._-]{0,63}$/i),
  class: z.enum(ACTION_CLASSES),
  technique: techniqueId.optional(),
  target: z.discriminatedUnion("kind", [
    z.strictObject({ kind: z.literal("range"), rangeId: ident }),
    z.strictObject({ kind: z.literal("verified-domain"), url: z.string() }),
    z.strictObject({ kind: z.literal("ci-runner"), url: z.string() }),
  ]),
});
export type Action = z.infer<typeof ActionSchema>;

const num = z.number().finite().nonnegative();
const StateSchema = z.object({
  startedAt: num,
  stepsUsed: num,
  tokensUsed: num,
  costUsd: num,
  killed: z.boolean(),
  /** domain -> time ownership was proved in THIS run (set by the runtime after verifyOwnership, never by an agent) */
  ownershipProvedAt: z.record(z.string(), num),
});
export type GuardState = z.infer<typeof StateSchema>;

const deny = (reason: DenyReason, detail: string): Decision => ({ ok: false, reason, detail });
const MAX_URL = 2048;

type Prelude = { ok: true; roe: Roe; state: GuardState } | { ok: false; reason: DenyReason; detail: string };

/** Everything that can be decided without reading the action: the ROE, the clock, the kill switch, the window and the budgets. */
function prelude(roeInput: unknown, now: number, stateInput: GuardState): Prelude {
  const refuse = (reason: DenyReason, detail: string): Prelude => ({ ok: false, reason, detail });
  const roeParsed = parseRoe(roeInput);
  if (!roeParsed.ok) return refuse("roe-invalid", `The rules of engagement are not valid: ${roeParsed.errors[0]}`);
  const roe = roeParsed.roe;
  if (typeof now !== "number" || !Number.isFinite(now)) return refuse("clock-invalid", "The clock reading is not a finite number.");
  const st = StateSchema.safeParse(stateInput);
  if (!st.success) return refuse("state-invalid", "The run state is not valid, so nothing can be allowed.");
  const state = st.data;
  if (state.startedAt > now) return refuse("state-invalid", "The run claims to have started in the future.");

  if (state.killed) return refuse("killed", "The kill switch was used. This run is stopped.");
  if (now < roe.window.notBefore) return refuse("not-yet-valid", "The approved time window has not started.");
  if (now >= roe.window.notAfter) return refuse("expired", "The approved time window has ended.");

  const b = roe.budgets;
  if (state.stepsUsed >= b.steps) return refuse("budget-steps", `The step budget of ${b.steps} is used up.`);
  if (state.tokensUsed >= b.tokens) return refuse("budget-tokens", `The token budget of ${b.tokens} is used up.`);
  if (now - state.startedAt >= b.wallMs) return refuse("budget-time", "The time budget for this run is used up.");
  if (state.costUsd >= b.costUsd) return refuse("budget-cost", `The cost budget of $${b.costUsd} is used up.`);
  return { ok: true, roe, state };
}

/** Can this run still do anything at all? The runtime asks this between model steps, with no action in hand. */
export function checkLimits(roeInput: unknown, now: number, stateInput: GuardState): Decision {
  const p = prelude(roeInput, now, stateInput);
  return p.ok ? { ok: true } : p;
}

export function allow(actionInput: unknown, roeInput: unknown, now: number, stateInput: GuardState): Decision {
  const p = prelude(roeInput, now, stateInput);
  if (!p.ok) return p;
  const { roe, state } = p;

  const parsed = ActionSchema.safeParse(actionInput);
  if (!parsed.success) return deny("action-invalid", "The requested action is malformed, so it was refused.");
  const a = parsed.data;

  if (!roe.agents.includes(a.agent)) return deny("agent-not-in-roe", `The ${a.agent} agent is not part of this run.`);
  if (classRank(a.class) > classRank(AGENT_CEILING[a.agent])) return deny("class-above-agent-ceiling", `The ${a.agent} agent may never take a "${a.class}" action.`);
  if (!(roe.allowedClasses as readonly string[]).includes(a.class)) return deny("class-not-in-roe", `"${a.class}" actions are not allowed in this run.`);

  if (a.technique !== undefined && roe.forbiddenTechniques.includes(a.technique)) return deny("technique-forbidden", `${a.technique} is explicitly forbidden in this run.`);
  if (a.class !== "observe" && a.technique === undefined) return deny("technique-missing", "Every action beyond observing must name the ATT&CK technique it uses.");
  if (a.technique !== undefined && !roe.allowedTechniques.includes(a.technique)) return deny("technique-not-allowed", `${a.technique} is not on this run's allowed list.`);

  return checkTarget(a, roe, now, state);
}

function checkTarget(a: Action, roe: Roe, now: number, state: GuardState): Decision {
  const t = a.target;
  if (t.kind === "range") {
    const ok = roe.targets.some((x) => x.kind === "range" && x.rangeId === t.rangeId);
    return ok ? { ok: true } : deny("target-not-in-roe", "That range is not part of this run.");
  }

  const ofKind = roe.targets.filter((x) => x.kind === t.kind);
  if (ofKind.length === 0) return deny("target-not-in-roe", `This run has no ${t.kind} target.`);
  if (classRank(a.class) > classRank(REAL_TARGET_CEILING)) return deny("class-not-allowed-on-target", "Only observing and non-intrusive probing may ever reach a real target.");

  const url = safeUrl(t.url);
  if (typeof url === "string") return deny("url-unsafe", url);

  if (t.kind === "ci-runner") {
    const match = ofKind.some((x) => x.kind === "ci-runner" && x.url === url.origin);
    return match ? { ok: true } : deny("host-mismatch", "That address is not the staging site this run was approved for.");
  }

  const host = url.hostname;
  const target = ofKind.find((x) => x.kind === "verified-domain" && x.domain === host);
  if (!target) return deny("host-mismatch", "That host is not the exact domain this run was approved for.");
  // Ownership must have been proved after this run started (so a domain that changed hands is never tested on an old proof), and not in the future.
  const proved = Object.hasOwn(state.ownershipProvedAt, host) ? state.ownershipProvedAt[host] : undefined;
  if (proved === undefined || proved < state.startedAt || proved > now) return deny("ownership-not-reproved", "Ownership of this domain was not proved at the start of this run, so nothing is sent to it.");
  return { ok: true };
}

/** A parsed URL, or the reason it is refused. https only, standard port, no credentials, never an IP address. */
function safeUrl(raw: string): URL | string {
  if (raw.length === 0 || raw.length > MAX_URL) return "The address is empty or too long.";
  let u: URL;
  try { u = new URL(raw); } catch { return "The address is not a valid URL."; }
  if (u.protocol !== "https:") return "Only https addresses are allowed.";
  if (u.username || u.password) return "Addresses with a login in them are refused.";
  if (u.port) return "Only the standard port is allowed.";
  if (isIP(u.hostname.replace(/^\[|\]$/g, ""))) return "IP addresses are refused; a host name is required.";
  return u;
}
