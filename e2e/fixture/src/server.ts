import { Client } from "pg";
import Stripe from "stripe";
export const db = new Client({ connectionString: process.env.DATABASE_URL });
export const stripe = new Stripe(process.env.STRIPE_KEY ?? "");
export function handler() { return "ok"; }
