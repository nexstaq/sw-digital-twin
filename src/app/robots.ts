import type { MetadataRoute } from "next";

const origin = () => (process.env.APP_URL ?? "https://sw-digital-twin.nexstaq.com").replace(/\/$/, "");

/** Crawlers may read the public pages. They may not read the API, or share links (a share link is a bearer secret). */
export default function robots(): MetadataRoute.Robots {
  return { rules: [{ userAgent: "*", allow: "/", disallow: ["/api/", "/s/"] }], sitemap: `${origin()}/sitemap.xml` };
}
