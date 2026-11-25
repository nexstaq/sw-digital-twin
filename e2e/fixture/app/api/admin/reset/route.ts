import { db } from "../../../../src/server";

// clears the demo data
export async function POST() {
  await db.query("DELETE FROM orders");
  return Response.json({ ok: true });
}
