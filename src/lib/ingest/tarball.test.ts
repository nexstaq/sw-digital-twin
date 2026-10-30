import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, existsSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { extractTar, safeEntryPath } from "./tarball";

const lim = { maxBytes: 1 << 20, maxFiles: 100, maxFileBytes: 1000, skipDir: (n: string) => n === "node_modules" };
const tmp = () => mkdtempSync(path.join(tmpdir(), "tar-test-"));
async function* chunks(b: Buffer, size = 700) { for (let i = 0; i < b.length; i += size) yield b.subarray(i, i + size); }

/** a one-file ustar archive with an arbitrary (possibly hostile) name */
function entry(name: string, body: string, type = "0"): Buffer {
  const h = Buffer.alloc(512);
  h.write(name, 0);
  h.write("0000644\0", 100);
  h.write(body.length.toString(8).padStart(11, "0") + "\0", 124);
  h.write(type, 156);
  const data = Buffer.alloc(Math.ceil(body.length / 512) * 512);
  data.write(body);
  return Buffer.concat([h, data]);
}

describe("extractTar", () => {
  it("unpacks a real git archive: strips the prefix, skips node_modules and big files, reads the commit sha", async () => {
    const repo = tmp();
    const git = (...a: string[]) => execFileSync("git", ["-C", repo, "-c", "user.email=t@t", "-c", "user.name=t", ...a], { encoding: "utf8" });
    git("init", "-q");
    mkdirSync(path.join(repo, "src")); mkdirSync(path.join(repo, "node_modules/x"), { recursive: true });
    writeFileSync(path.join(repo, "src/app.ts"), "export {}");
    writeFileSync(path.join(repo, "package.json"), "{}");
    writeFileSync(path.join(repo, "node_modules/x/i.js"), "no");
    writeFileSync(path.join(repo, "big.bin"), "x".repeat(5000));
    git("add", "-A"); git("commit", "-qm", "init");
    const head = git("rev-parse", "HEAD").trim();
    const tarball = execFileSync("git", ["-C", repo, "archive", "--format=tar", "--prefix=o-r-abc1234/", "HEAD"], { maxBuffer: 1 << 24 });

    const out = tmp();
    const r = await extractTar(chunks(tarball), out, lim);
    expect(r.sha).toBe(head);
    expect(readFileSync(path.join(out, "src/app.ts"), "utf8")).toBe("export {}");
    expect(existsSync(path.join(out, "package.json"))).toBe(true);
    expect(existsSync(path.join(out, "node_modules"))).toBe(false);
    expect(existsSync(path.join(out, "big.bin"))).toBe(false);
    rmSync(repo, { recursive: true }); rmSync(out, { recursive: true });
  });

  it("never writes outside the destination, and ignores links", async () => {
    const out = tmp();
    const evil = Buffer.concat([
      entry("o-r-1/../../escape.txt", "pwn"),
      entry("o-r-1/ok.txt", "fine"),
      entry("o-r-1/link", "", "2"),
      Buffer.alloc(1024),
    ]);
    await extractTar(chunks(evil), out, lim);
    expect(existsSync(path.join(out, "../escape.txt"))).toBe(false);
    expect(readFileSync(path.join(out, "ok.txt"), "utf8")).toBe("fine");
    expect(existsSync(path.join(out, "link"))).toBe(false);
    rmSync(out, { recursive: true });
  });

  it("refuses an archive over the file limit", async () => {
    const out = tmp();
    const many = Buffer.concat([entry("p/a", "1"), entry("p/b", "2"), entry("p/c", "3"), Buffer.alloc(1024)]);
    await expect(extractTar(chunks(many), out, { ...lim, maxFiles: 2 })).rejects.toThrow(/too large/);
    rmSync(out, { recursive: true });
  });
});

describe("safeEntryPath", () => {
  const skip = (n: string) => n === "node_modules";
  it("accepts normal paths and rejects hostile ones", () => {
    expect(safeEntryPath("o-r-1/src/a.ts", skip)).toBe("src/a.ts");
    for (const bad of ["o-r-1/../x", "/abs/x", "o-r-1/a\\b", "o-r-1/node_modules/x/y.js", "o-r-1/.git/config", "o-r-1/"]) expect(safeEntryPath(bad, skip)).toBeNull();
  });
});
