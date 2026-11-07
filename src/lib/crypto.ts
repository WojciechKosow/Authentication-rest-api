import { createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";

/** URL-safe random token with `bytes` bytes of entropy and an optional prefix. */
export function randomToken(prefix: string, bytes = 32): string {
  return `${prefix}${randomBytes(bytes).toString("base64url")}`;
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function hmacSha256Hex(key: string | Buffer, message: string): string {
  return createHmac("sha256", key).update(message, "utf8").digest("hex");
}

/** Constant-time string comparison (compares SHA-256 digests so lengths never leak). */
export function safeEqual(a: string, b: string): boolean {
  const da = createHash("sha256").update(a, "utf8").digest();
  const db = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(da, db) && a.length === b.length;
}

/** HKDF-SHA256 derivation of a 32-byte per-application key from a master secret. */
export function deriveKey(masterSecret: string, salt: string, info: string): Buffer {
  return Buffer.from(hkdfSync("sha256", Buffer.from(masterSecret, "utf8"), Buffer.from(salt, "utf8"), Buffer.from(info, "utf8"), 32));
}
