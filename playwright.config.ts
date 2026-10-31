import { defineConfig } from "@playwright/test";

const APP = 3300, MOCK = 4010;

/**
 * Hermetic e2e: a production build of the app against a mock GitHub (e2e/mock-github.mjs). No network, no real credentials.
 * Builds into .next-e2e, so it is safe to run while `next dev` is up.
 */
export default defineConfig({
  testDir: "e2e",
  testMatch: "*.spec.ts",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : "list",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  use: { baseURL: `http://localhost:${APP}`, viewport: { width: 1440, height: 900 }, trace: "retain-on-failure", screenshot: "only-on-failure" },
  webServer: [
    { command: "node e2e/mock-github.mjs", url: `http://localhost:${MOCK}/__health`, reuseExistingServer: !process.env.CI, env: { MOCK_PORT: String(MOCK) } },
    {
      command: `npx next build && npx next start -p ${APP}`,
      url: `http://localhost:${APP}/api/auth/me`,
      reuseExistingServer: !process.env.CI,
      timeout: 300_000,
      env: {
        TWIN_DIST: ".next-e2e",
        TWIN_FETCH: "tarball",
        TWIN_PERSIST: "memory",
        RATE_LIMIT_SCALE: "5",
        APP_URL: `http://localhost:${APP}`,
        GITHUB_API_URL: `http://localhost:${MOCK}`,
        GITHUB_WEB_URL: `http://localhost:${MOCK}`,
        OSV_API_URL: `http://localhost:${MOCK}`,
        GITHUB_ACTIONS_OIDC_ISSUER: `http://localhost:${MOCK}`, // the mock signs CI tokens with a real key and serves its JWKS
        GITHUB_APP_CLIENT_ID: "e2e-client",
        GITHUB_APP_CLIENT_SECRET: "e2e-secret",
        GITHUB_APP_SLUG: "e2e-app",
        SESSION_SECRET: "e2e".repeat(22),
        // Next also reads .env.local; blank anything real so a test run can never reach a real database, model, GitHub App or connector
        DATABASE_URL: "", POSTGRES_URL: "", VERCEL_OIDC_TOKEN: "", AI_GATEWAY_API_KEY: "", GOOGLE_GENERATIVE_AI_API_KEY: "",
        GITHUB_APP_ID: "", GITHUB_APP_PRIVATE_KEY: "", GITHUB_TOKEN: "", GITHUB_WEBHOOK_SECRET: "", CONNECTOR_REPOS: "", OTLP_TOKEN: "", SENTRY_TOKEN: "", VERCEL_TOKEN: "",
      },
    },
  ],
});
