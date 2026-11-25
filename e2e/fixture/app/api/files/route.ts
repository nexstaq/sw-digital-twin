import { readFile } from "node:fs/promises";
import path from "node:path";

// serves an exported report by name
export async function GET(req: Request) {
  const body = await readFile(path.join("/srv/exports", new URL(req.url).searchParams.get("name") ?? ""));
  return new Response(body);
}
