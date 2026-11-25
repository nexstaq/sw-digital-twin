import { db } from "../../../src/server";

// looks up one invoice; the id is forced to a number before it goes anywhere near the query
export async function GET(req: Request) {
  const id = Number(new URL(req.url).searchParams.get("id"));
  if (!Number.isInteger(id)) return Response.json({ error: "bad id" }, { status: 400 });
  const rows = await db.query(`SELECT * FROM invoices WHERE id = ${id}`);
  return Response.json(rows);
}
