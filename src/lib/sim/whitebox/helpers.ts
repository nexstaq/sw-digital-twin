// Test helpers for the white-box agent. Not imported by production code.
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { Finding } from "@/lib/security/types";
import type { Excerpt } from "./source";
import { FIXTURE_DIR } from "./world";

/** what the app's source reader would return: the lines around the finding, read from the fixture on disk */
export async function diskExcerpt(f: Finding, span = 12): Promise<Excerpt | null> {
  if (!f.line) return null;
  const text = await readFile(path.join(FIXTURE_DIR, f.path), "utf8").catch(() => null);
  if (text === null) return null;
  const all = text.split("\n");
  const start = Math.max(1, f.line - span);
  return { path: f.path, startLine: start, lines: all.slice(start - 1, f.line + span) };
}
