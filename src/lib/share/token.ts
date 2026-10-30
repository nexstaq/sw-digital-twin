import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export interface Share {
  id: string;
  /** sha256 of the secret. The secret itself is shown once, when the link is created, and never stored. */
  hash: string;
  label?: string;
  createdBy: string;
  createdAt: number;
  revokedAt?: number;
}

const SECRET = /^[A-Za-z0-9_-]{32}$/;

export const newSecret = () => randomBytes(24).toString("base64url"); // 24 bytes = 192 bits = 32 chars
export const hashSecret = (secret: string) => createHash("sha256").update(secret).digest("hex");
export const newShareId = () => randomBytes(6).toString("hex");

/** The live share that this secret opens, or null. Compares hashes in constant time and ignores revoked links. */
export function matchShare(shares: Share[], secret: string): Share | null {
  if (!SECRET.test(secret)) return null;
  const want = Buffer.from(hashSecret(secret), "hex");
  let found: Share | null = null;
  for (const s of shares) { // no early exit: time does not reveal which link matched
    const have = Buffer.from(s.hash, "hex");
    if (have.length === want.length && timingSafeEqual(have, want) && !s.revokedAt) found = s;
  }
  return found;
}
