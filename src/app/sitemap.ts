import type { MetadataRoute } from "next";

const origin = () => (process.env.APP_URL ?? "https://sw-digital-twin.nexstaq.com").replace(/\/$/, "");

export default function sitemap(): MetadataRoute.Sitemap {
  return ["/", "/about", "/privacy", "/demo", "/demo/incident"].map((p) => ({ url: `${origin()}${p}` }));
}
