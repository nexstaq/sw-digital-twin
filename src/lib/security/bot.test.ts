import { describe, expect, it, vi } from "vitest";
import { denyBots } from "./bot";
import { parseSse } from "../sse";

describe("denyBots", () => {
  it("blocks a bot with 403 and lets a human through", async () => {
    const r = await denyBots({ enabled: true, check: async () => ({ isBot: true }) });
    expect(r?.status).toBe(403);
    expect(await denyBots({ enabled: true, check: async () => ({ isBot: false }) })).toBeNull();
  });
  it("is off outside Vercel and never calls the check", async () => {
    const check = vi.fn(async () => ({ isBot: true }));
    expect(await denyBots({ enabled: false, check })).toBeNull();
    expect(check).not.toHaveBeenCalled();
  });
  it("fails open when the check itself breaks", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(await denyBots({ enabled: true, check: async () => { throw new Error("down"); } })).toBeNull();
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });
});

describe("parseSse", () => {
  it("returns complete frames and keeps the unfinished tail", () => {
    const r = parseSse('data: {"a":1}\n\ndata: {"b":2}\n\ndata: {"c"');
    expect(r.events).toEqual(['{"a":1}', '{"b":2}']);
    expect(r.rest).toBe('data: {"c"');
  });
  it("handles CRLF, joins multi-line data, and skips comments and empty frames", () => {
    expect(parseSse(": keepalive\n\ndata: x\r\ndata: y\r\n\n\n\n").events).toEqual(["x\ny"]);
  });
  it("a frame split across chunks is delivered once it completes", () => {
    const a = parseSse('data: {"ty');
    expect(a.events).toEqual([]);
    expect(parseSse(a.rest + 'pe":"done"}\n\n').events).toEqual(['{"type":"done"}']);
  });
});
