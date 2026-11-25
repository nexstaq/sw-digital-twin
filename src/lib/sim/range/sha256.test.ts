import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { sha256Hex } from "./sha256";

const reference = (s: string) => createHash("sha256").update(s).digest("hex");

describe("sha256Hex agrees with node:crypto", () => {
  it.each([
    ["", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    ["abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"],
    ["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"],
  ])("known vector %j", (input, hex) => { expect(sha256Hex(input)).toBe(hex); });

  it("every length around the block boundaries (55 to 66 bytes, where padding changes shape)", () => {
    for (let n = 0; n <= 130; n++) { const s = "x".repeat(n); expect(sha256Hex(s), `length ${n}`).toBe(reference(s)); }
  });
  it("random text, including multi-byte characters", () => {
    let seed = 12345;
    const rnd = () => (seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 4294967296;
    const pool = "abcXYZ019 _-/:{}[]\"\\é漢字🙂\n";
    for (let i = 0; i < 300; i++) {
      const len = Math.floor(rnd() * 400);
      let s = ""; for (let k = 0; k < len; k++) s += [...pool][Math.floor(rnd() * [...pool].length)];
      expect(sha256Hex(s)).toBe(reference(s));
    }
  });
  it("a large input", () => { const s = "abc123".repeat(50_000); expect(sha256Hex(s)).toBe(reference(s)); });
});
