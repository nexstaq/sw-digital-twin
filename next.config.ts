import type { NextConfig } from "next";
import { withBotId } from "botid/next/config";
import { securityHeaders } from "./src/lib/security/headers";

const TREE_SITTER_FILES = [
  "./node_modules/web-tree-sitter/tree-sitter.wasm",
  "./node_modules/tree-sitter-wasms/out/tree-sitter-{typescript,tsx,javascript,python}.wasm",
];

const nextConfig: NextConfig = {
  cacheComponents: true,
  poweredByHeader: false,
  // the e2e suite builds into its own folder so it can never clobber a running `next dev` (they share .next otherwise)
  distDir: process.env.TWIN_DIST || ".next",
  async headers() {
    const prod = process.env.NODE_ENV === "production";
    return [
      { source: "/api/badge/:owner/:repo", headers: securityHeaders(prod, { embeddable: true }) },
      // the report is a static document: no scripts are allowed to run in it, whatever the findings contain
      { source: "/api/security/report", headers: securityHeaders(prod, { locked: true }) },
      { source: "/((?!api/badge/|api/security/report).*)", headers: securityHeaders(prod) },
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
    // both functions parse source with tree-sitter, so both must ship the grammars
    "/api/scan": TREE_SITTER_FILES,
    "/api/security/scan": TREE_SITTER_FILES,
  },
};

export default withBotId(nextConfig);
