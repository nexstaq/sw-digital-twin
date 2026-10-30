import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

export interface TarLimits {
  /** total bytes written to disk */
  maxBytes: number;
  maxFiles: number;
  /** files above this are not written (the analysers would not read them anyway) */
  maxFileBytes: number;
  /** directory names that are never written (node_modules, dist, …) */
  skipDir: (name: string) => boolean;
}

const BLOCK = 512;
const str = (b: Buffer, from: number, len: number) => {
  const s = b.subarray(from, from + len);
  const z = s.indexOf(0);
  return s.subarray(0, z < 0 ? s.length : z).toString("utf8");
};

/** `20 path=a/b\n` records of a pax header. */
function paxRecords(body: Buffer): Record<string, string> {
  const out: Record<string, string> = {};
  let i = 0;
  while (i < body.length) {
    const sp = body.indexOf(0x20, i);
    if (sp < 0) break;
    const len = Number(body.subarray(i, sp).toString());
    if (!Number.isInteger(len) || len <= sp - i + 1 || i + len > body.length) break;
    const rec = body.subarray(sp + 1, i + len - 1).toString("utf8");
    const eq = rec.indexOf("=");
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}

/** Repo-relative path from an archive entry name, or null when it is unsafe or not wanted. Drops the "owner-repo-sha/" prefix. */
export function safeEntryPath(name: string, skipDir: TarLimits["skipDir"]): string | null {
  if (!name || name.includes("\0") || name.includes("\\") || name.startsWith("/")) return null;
  const parts = name.split("/").filter(Boolean).slice(1);
  if (parts.length === 0 || parts.some((p) => p === ".." || p === ".")) return null;
  if (parts.slice(0, -1).some(skipDir) || parts[0] === ".git") return null;
  return parts.join("/");
}

/**
 * Unpacks a (gunzipped) tar stream into `dest` without executing or linking anything: only regular files are written,
 * symlinks/hardlinks/devices are ignored, and any path that would leave `dest` is dropped. Memory stays bounded because a
 * file larger than `maxFileBytes` is skipped rather than buffered.
 * Returns the commit sha from GitHub's pax header when present.
 */
export async function extractTar(source: AsyncIterable<Uint8Array>, dest: string, lim: TarLimits): Promise<{ sha?: string; files: number }> {
  const root = path.resolve(dest) + path.sep;
  let buf = Buffer.alloc(0);
  let sha: string | undefined;
  let files = 0;
  let bytes = 0;
  let nextPath: string | undefined;

  type State =
    | { k: "header" }
    | { k: "collect"; type: string; name: string; size: number }
    | { k: "skip"; left: number }
  let st: State = { k: "header" };
  let ended = false;

  const padded = (n: number) => Math.ceil(n / BLOCK) * BLOCK;

  for await (const chunk of source) {
    if (ended) continue;
    buf = buf.length ? Buffer.concat([buf, chunk]) : Buffer.from(chunk);
    for (;;) {
      if (st.k === "skip") {
        const take = Math.min(st.left, buf.length);
        buf = buf.subarray(take);
        st.left -= take;
        if (st.left > 0) break;
        st = { k: "header" };
      } else if (st.k === "header") {
        if (buf.length < BLOCK) break;
        const h = buf.subarray(0, BLOCK);
        buf = buf.subarray(BLOCK);
        if (h.every((x) => x === 0)) { ended = true; break; }
        const type = String.fromCharCode(h[156] || 0x30);
        const size = parseInt(str(h, 124, 12).trim() || "0", 8);
        if (!Number.isFinite(size) || size < 0) throw new Error("Corrupt archive");
        const prefix = str(h, 345, 155);
        const name = nextPath ?? (prefix ? `${prefix}/${str(h, 0, 100)}` : str(h, 0, 100));
        const meta = type === "x" || type === "g" || type === "L";
        const regular = type === "0" || type === "\0";
        if (meta && size > 1 << 20) throw new Error("Corrupt archive");
        if (meta) st = { k: "collect", type, name, size };
        else if (regular && size <= lim.maxFileBytes) st = { k: "collect", type: "0", name, size };
        else st = { k: "skip", left: padded(size) };
        if (!meta) nextPath = undefined;
      } else {
        const total = padded(st.size);
        if (buf.length < total) break;
        const body = buf.subarray(0, st.size);
        buf = buf.subarray(total);
        if (st.type === "g") sha ??= /^[0-9a-f]{40}$/.exec(paxRecords(body).comment ?? "")?.[0];
        else if (st.type === "x") nextPath = paxRecords(body).path ?? nextPath;
        else if (st.type === "L") nextPath = str(body, 0, body.length);
        else {
          const rel = safeEntryPath(st.name, lim.skipDir);
          const abs = rel && path.resolve(dest, rel);
          if (abs && abs.startsWith(root)) {
            if (++files > lim.maxFiles || (bytes += st.size) > lim.maxBytes) throw new Error("Repository is too large to analyse");
            await mkdir(path.dirname(abs), { recursive: true });
            await writeFile(abs, body, { mode: 0o644 });
          }
        }
        st = { k: "header" };
      }
    }
  }
  return { sha, files };
}
