export interface Header { key: string; value: string }

/**
 * Browser-side hardening, set on every response.
 *
 * The CSP is static, not nonce-based: nonces force every page to render per request (see Next's CSP guide), which would
 * undo the prerendering this app relies on. So `script-src` needs 'unsafe-inline' for Next's own bootstrap scripts. What the
 * policy still buys: no eval, no plugins, no foreign script/connect origins, no framing, no <base> or form hijacking.
 */
export function securityHeaders(prod: boolean, o: { embeddable?: boolean; /** a static document that needs no scripts at all (the security report) */ locked?: boolean } = {}): Header[] {
  const csp = o.locked ? "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" : [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline'${prod ? "" : " 'unsafe-eval'"}`, // dev only: React uses eval for readable stack traces
    "style-src 'self' 'unsafe-inline'", // React Flow and Framer Motion set inline styles
    "img-src 'self' data: blob: https://avatars.githubusercontent.com",
    "font-src 'self' data:",
    "connect-src 'self'",
    "worker-src 'self' blob:", // the layout engine can spin up a worker
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    ...(prod ? ["upgrade-insecure-requests"] : []),
  ].join("; ");

  return [
    { key: "Content-Security-Policy", value: csp },
    { key: "X-Content-Type-Options", value: "nosniff" },
    { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
    { key: "X-Frame-Options", value: "DENY" }, // older browsers that ignore frame-ancestors
    { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" },
    { key: "Cross-Origin-Opener-Policy", value: "same-origin-allow-popups" },
    // an embeddable image (the badge) must be loadable from other sites; nothing else is
    { key: "Cross-Origin-Resource-Policy", value: o.embeddable ? "cross-origin" : "same-origin" },
    ...(prod ? [{ key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains" }] : []),
  ];
}
