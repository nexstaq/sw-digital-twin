import { db } from "../../../src/server";

// marks an order as paid
export async function POST(req: Request) {
  await db.query(`UPDATE orders SET paid = true WHERE id = ${new URL(req.url).searchParams.get("id")}`);
  return Response.json({ ok: true });
}
