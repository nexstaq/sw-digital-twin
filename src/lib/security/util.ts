import { createHash } from "node:crypto";

/** Short stable id from the parts that identify a finding. Line NUMBERS are not among them, so edits above do not make it "new". */
export const fingerprint = (...parts: (string | number | undefined)[]) => createHash("sha256").update(parts.map((p) => p ?? "").join("\u0000")).digest("hex").slice(0, 16);

/** 1-based line of the first line that matches, or undefined. */
export function lineOf(text: string, match: string | RegExp, from = 0): number | undefined {
  const lines = text.split("\n");
  for (let i = from; i < lines.length; i++) if (typeof match === "string" ? lines[i].includes(match) : match.test(lines[i])) return i + 1;
  return undefined;
}

export const isTestPath = (p: string) => /(^|\/)(tests?|__tests__|spec|e2e|fixtures?|testdata|mocks?|examples?|samples?|docs?)(\/|$)|\.(test|spec)\.[jt]sx?$|_test\.(go|py)$/i.test(p);
