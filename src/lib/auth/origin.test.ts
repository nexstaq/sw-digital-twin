import { describe, expect, it } from "vitest";
import { appOrigin, secureCookies } from "./origin";

const req = (host: string, o: { proto?: string; forwardedHost?: string } = {}) =>
  new Request(`${o.proto ?? "https"}://${host}/api/auth/login`, { headers: { ...(o.forwardedHost ? { "x-forwarded-host": o.forwardedHost, "x-forwarded-proto": o.proto ?? "https" } : {}) } });

const ENV = { APP_URL: "https://app.example.com/", APP_ALIAS_URLS: "https://alias.vercel.app, https://other.example.org/" } as unknown as NodeJS.ProcessEnv;

describe("appOrigin", () => {
  it("uses the request's origin when it is the primary or an allow-listed alias", () => {
    expect(appOrigin(req("app.example.com"), ENV)).toBe("https://app.example.com");
    expect(appOrigin(req("alias.vercel.app"), ENV)).toBe("https://alias.vercel.app");
    expect(appOrigin(req("other.example.org"), ENV)).toBe("https://other.example.org");
  });
  it("any other host, including a spoofed one, falls back to the primary", () => {
    expect(appOrigin(req("evil.example.net"), ENV)).toBe("https://app.example.com");
    expect(appOrigin(req("app.example.com", { forwardedHost: "evil.example.net" }), ENV)).toBe("https://app.example.com");
    expect(appOrigin(req("alias.vercel.app.evil.net"), ENV)).toBe("https://app.example.com"); // a look-alike is not an alias
    expect(appOrigin(req("alias.vercel.app", { proto: "http" }), ENV)).toBe("https://app.example.com"); // wrong scheme is not the alias either
  });
  it("honours the platform's forwarded host for an allow-listed alias", () => {
    expect(appOrigin(req("internal-lambda-host", { forwardedHost: "alias.vercel.app" }), ENV)).toBe("https://alias.vercel.app");
  });
  it("without aliases nothing changes: APP_URL always wins", () => {
    expect(appOrigin(req("alias.vercel.app"), { APP_URL: "https://app.example.com" } as unknown as NodeJS.ProcessEnv)).toBe("https://app.example.com");
  });
  it("without APP_URL (local dev) it is whatever the request says", () => {
    expect(appOrigin(req("localhost:3000", { proto: "http" }), {} as NodeJS.ProcessEnv)).toBe("http://localhost:3000");
  });
  it("cookies are Secure exactly when the chosen origin is https", () => {
    expect(secureCookies(req("alias.vercel.app"), ENV)).toBe(true);
    expect(secureCookies(req("localhost:3000", { proto: "http" }), {} as NodeJS.ProcessEnv)).toBe(false);
  });
});
