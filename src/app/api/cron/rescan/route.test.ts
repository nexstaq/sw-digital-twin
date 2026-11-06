import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/security/schedule/rescan", () => ({ runDueRescans: vi.fn(async () => ({ due: 0, ran: [], skipped: 0 })) }));
import { GET } from "./route";

const call = (auth?: string) => GET(new Request("http://x/api/cron/rescan", { headers: auth ? { authorization: auth } : {} }));
afterEach(() => { delete process.env.CRON_SECRET; });

describe("cron rescan endpoint", () => {
  it("refuses everyone when no secret is configured", async () => { expect((await call("Bearer anything")).status).toBe(503); });
  it("rejects a missing or wrong secret", async () => {
    process.env.CRON_SECRET = "s3cret-value";
    expect((await call()).status).toBe(401);
    expect((await call("Bearer nope")).status).toBe(401);
    expect((await call("s3cret-value")).status).toBe(401);
  });
  it("runs with the right secret", async () => {
    process.env.CRON_SECRET = "s3cret-value";
    const r = await call("Bearer s3cret-value");
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ due: 0, ran: [], skipped: 0 });
  });
});
