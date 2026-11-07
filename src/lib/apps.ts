import { randomBytes } from "node:crypto";
import type { Application } from "@/generated/prisma/client";
import { getConfig } from "./config";
import { deriveKey, randomToken, safeEqual, sha256Hex } from "./crypto";
import { getDb } from "./db";
import { ApiError } from "./errors";

export type AppRecord = Application;

export const APP_ID_PATTERN = /^app_[a-f0-9]{24}$/;

export function generateAppId(): string {
  return `app_${randomBytes(12).toString("hex")}`;
}

export function generateAppSecret(): string {
  return randomToken("sk_", 32);
}

export function hashAppSecret(secret: string): string {
  return sha256Hex(secret);
}

/** Per-application HMAC secret used to sign requests sent to the developer backend. */
export function integrationSigningSecret(app: Pick<AppRecord, "id" | "integrationSecretVersion">): string {
  const key = deriveKey(getConfig().integrationMasterSecret, app.id, `integration-hmac:v${app.integrationSecretVersion}`);
  return `whsec_${key.toString("base64url")}`;
}

/** Per-application JWT signing key (HS256). Never leaves the server. */
export function jwtSigningKey(app: Pick<AppRecord, "id" | "jwtKeyVersion">): Uint8Array {
  return new Uint8Array(deriveKey(getConfig().jwtMasterSecret, app.id, `jwt-hs256:v${app.jwtKeyVersion}`));
}

/**
 * Authenticate the calling application via X-App-Id + X-App-Secret.
 * Optionally binds the application to a RapidAPI user (X-RapidAPI-User),
 * so a leaked app secret cannot be used from another RapidAPI subscription.
 */
export async function authenticateApp(request: Request): Promise<AppRecord> {
  const appId = request.headers.get("x-app-id")?.trim();
  const secret = request.headers.get("x-app-secret")?.trim();
  if (!appId || !secret) throw new ApiError("MISSING_APP_CREDENTIALS");
  if (!APP_ID_PATTERN.test(appId) || secret.length > 200) throw new ApiError("INVALID_APP_CREDENTIALS");

  const app = await getDb().application.findUnique({ where: { id: appId } });
  // Always compare, even when the app is missing, to keep timing uniform.
  const valid = safeEqual(hashAppSecret(secret), app?.secretHash ?? "0".repeat(64));
  if (!app || !valid || !app.isActive) throw new ApiError("INVALID_APP_CREDENTIALS");

  if (app.rapidApiUser) {
    const rapidUser = request.headers.get("x-rapidapi-user");
    if (!rapidUser || !safeEqual(rapidUser, app.rapidApiUser)) throw new ApiError("APP_ACCESS_DENIED");
  }
  return app;
}
