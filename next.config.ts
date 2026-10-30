import type { NextConfig } from "next";
import { withBotId } from "botid/next/config";
import { securityHeaders } from "./src/lib/security/headers";

const nextConfig: NextConfig = {
  cacheComponents: true,
  poweredByHeader: false,
  // the e2e suite builds into its own folder so it can never clobber a running `next dev` (they share .next otherwise)
  distDir: process.env.TWIN_DIST || ".next",
  async headers() {
    const prod = process.env.NODE_ENV === "production";
    return [
      { source: "/api/badge/:owner/:repo", headers: securityHeaders(prod, { embeddable: true }) },
      { source: "/((?!api/badge/).*)", headers: securityHeaders(prod) },
    ];
  },
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  // tree-sitter loads its grammars as .wasm files at runtime; keep them out of the bundle
  // but make sure they ship with the scan function when deployed.
  serverExternalPackages: ["web-tree-sitter", "tree-sitter-wasms"],
  outputFileTracingIncludes: {
    "/api/scan": [
      "./node_modules/web-tree-sitter/tree-sitter.wasm",
      "./node_modules/tree-sitter-wasms/out/tree-sitter-{typescript,tsx,javascript,python}.wasm",
    ],
  },
};

export default withBotId(nextConfig);
