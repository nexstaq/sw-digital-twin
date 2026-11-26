import type { z } from "zod";
import type { Action } from "../scope";
import type { Agent, ActionClass } from "../roe";
import type { UntrustedSource } from "./untrusted";

/**
 * What a tool is. A tool states what KIND of action a call is, which technique it uses and what it targets, all from its own
 * input, and the runtime hands exactly that to `allow()` before anything runs. A tool never decides whether it may run.
 *
 * `run` receives the validated input and a context that holds one thing: an abort signal. There is deliberately no way to reach
 * the rules of engagement, the run state, the budgets, the audit log, the kill switch or an approval from inside a tool. The tool's
 * dependencies (a range, a transport) are closed over by whoever builds it, and are things the agent is allowed to use anyway.
 */

export interface ToolContext { readonly signal: AbortSignal }

export interface SimTool<I = unknown, O = unknown> {
  name: string;
  description: string;
  inputSchema: z.ZodType<I>;
  /** what this call is. May depend on the input (a request carrying a payload class is an exploit, one without is a probe). */
  classOf(input: I): ActionClass;
  techniqueOf(input: I): string | undefined;
  targetOf(input: I): Action["target"];
  /** where the output came from, so it is quoted with the right label */
  source: UntrustedSource;
  /** one harmless line for the audit log. Never the output itself. */
  summarize(output: O): string;
  run(input: I, ctx: ToolContext): Promise<O>;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type AnyTool = SimTool<any, any>;

export const defineTool = <I, O>(t: SimTool<I, O>): SimTool<I, O> => t;

/**
 * Which tools each agent may EVER be given. Enforced when a run is created and again on every call. The model cannot reach a tool
 * that is not here, whatever it is told to call. (The rules of engagement and the agent ceilings then decide each individual call.)
 */
export const TOOL_ALLOWLIST: Record<Agent, readonly string[]> = {
  whitebox: ["range_inspect", "range_request"],
  graybox: ["range_inspect", "range_request", "http_probe", "ci_plan_request"],
  redteam: ["range_inspect", "range_request", "range_trigger", "range_flow", "ci_plan_request"],
  blue: ["range_inspect"],
  narrator: ["range_inspect"],
};
