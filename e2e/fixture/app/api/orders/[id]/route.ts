import { db } from "../../../../src/server";

// returns one order by id
export async function GET(_req: Request, ctx: { params: { id: string } }) {
  const rows = await db.query("SELECT * FROM orders WHERE id = $1", [ctx.params.id]);
  return Response.json(rows);
}
