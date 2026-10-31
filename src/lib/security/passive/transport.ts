import { BlockedError, resolveMx, resolveTxt, safeCert, safeRequest, type CertInfo, type Response } from "./net";

export interface ReqOpts { scheme?: "http" | "https"; method?: "GET" | "HEAD" | "OPTIONS"; headers?: Record<string, string>; maxBytes?: number }

/** Everything the checks need from the outside world, in one place, so it can be replaced in tests. */
export interface Transport {
  request(host: string, path: string, o?: ReqOpts): Promise<Response>;
  cert(host: string): Promise<CertInfo>;
  txt(name: string): Promise<string[]>;
  mx(name: string): Promise<string[]>;
}

/** The real thing: every request goes through the SSRF guard in net.ts. */
export function realTransport(): Transport {
  return { request: (host, path, o) => safeRequest(host, path, o), cert: (host) => safeCert(host), txt: resolveTxt, mx: resolveMx };
}

/**
 * For the end-to-end suite only: routes everything to a fixture server that pretends to be the internet, so the whole flow can be tested
 * without network access. Ignored on Vercel, and it needs an explicit environment variable, so production can never use it.
 */
export function fixtureTransport(base: string): Transport {
  const call = async <T,>(kind: string, q: Record<string, string>): Promise<T> => {
    const res = await fetch(`${base}/__passive/${kind}?${new URLSearchParams(q)}`, { cache: "no-store" });
    const body = (await res.json()) as T & { error?: string; blocked?: boolean };
    if (!res.ok) { if (body.blocked) throw new BlockedError(body.error ?? "blocked"); throw new Error(body.error ?? `fixture answered ${res.status}`); }
    return body;
  };
  return {
    request: (host, path, o) => call<Response>("request", { host, path, scheme: o?.scheme ?? "https", method: o?.method ?? "GET", headers: JSON.stringify(o?.headers ?? {}) }),
    cert: (host) => call<CertInfo>("cert", { host }),
    txt: (name) => call<string[]>("dns", { type: "TXT", name }),
    mx: (name) => call<string[]>("dns", { type: "MX", name }),
  };
}

export function getTransport(): Transport {
  const fixture = process.env.PASSIVE_CHECK_FIXTURE_URL;
  return fixture && !process.env.VERCEL ? fixtureTransport(fixture.replace(/\/$/, "")) : realTransport();
}
