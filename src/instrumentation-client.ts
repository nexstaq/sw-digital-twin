import { initBotId } from "botid/client/core";

// BotID attaches its token to these fetch calls; the server checks it (see src/lib/security/bot.ts).
initBotId({
  protect: [
    { path: "/api/scan", method: "GET" },
    { path: "/api/ask", method: "POST" },
    { path: "/api/security/scan", method: "POST" },
    { path: "/api/security/explain", method: "POST" },
  ],
});
