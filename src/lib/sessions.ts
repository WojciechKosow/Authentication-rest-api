import { AppRecord } from "./apps";
import { getConfig } from "./config";
import { randomToken, sha256Hex } from "./crypto";
import { getDb } from "./db";
import { ApiError } from "./errors";
import { AccessTokenClaims, signAccessToken, verifyAccessToken } from "./jwt";
import { logger } from "./logger";

export const REFRESH_TOKEN_PATTERN = /^rt_[A-Za-z0-9_-]{43}$/;

export interface TokenBundle {
  token_type: "Bearer";
  access_token: string;
  access_token_expires_at: string;
  expires_in: number;
  refresh_token: string;
  refresh_token_expires_at: string;
  session_id: string;
}

async function issueTokens(app: AppRecord, userId: string, sessionId: string, refreshToken: string, refreshExpiresAt: Date) {
  const access = await signAccessToken(app, userId, sessionId);
  const bundle: TokenBundle = {
    token_type: "Bearer",
    access_token: access.token,
    access_token_expires_at: access.expiresAt.toISOString(),
    expires_in: getConfig().accessTokenTtlSeconds,
    refresh_token: refreshToken,
    refresh_token_expires_at: refreshExpiresAt.toISOString(),
    session_id: sessionId,
  };
  return bundle;
}

/** Start a new session (= new refresh token family) for a verified user. */
export async function createSession(app: AppRecord, userId: string): Promise<TokenBundle> {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + getConfig().refreshTokenTtlSeconds * 1000);
  const refreshToken = randomToken("rt_", 32);
  const session = await getDb().session.create({
    data: {
      appId: app.id,
      userId,
      expiresAt,
      lastUsedAt: now,
      refreshTokens: { create: { tokenHash: sha256Hex(refreshToken), expiresAt } },
    },
  });
  return issueTokens(app, userId, session.id, refreshToken, expiresAt);
}

export async function revokeSession(sessionId: string, reason: string): Promise<void> {
  await getDb().session.updateMany({
    where: { id: sessionId, revokedAt: null },
    data: { revokedAt: new Date(), revokedReason: reason },
  });
}

export async function revokeAllUserSessions(appId: string, userId: string, reason: string): Promise<number> {
  const res = await getDb().session.updateMany({
    where: { appId, userId, revokedAt: null },
    data: { revokedAt: new Date(), revokedReason: reason },
  });
  return res.count;
}

/**
 * Exchange a refresh token for a new access + refresh token pair (rotation).
 * A refresh token can be used exactly once; presenting it again revokes the
 * whole session (token family), protecting against stolen-token replay.
 */
export async function rotateRefreshToken(app: AppRecord, refreshToken: string): Promise<TokenBundle> {
  const db = getDb();
  const now = new Date();
  const record = await db.refreshToken.findUnique({
    where: { tokenHash: sha256Hex(refreshToken) },
    include: { session: true },
  });

  // Unknown token, or a token that belongs to a different application: indistinguishable to the caller.
  if (!record || record.session.appId !== app.id) throw new ApiError("INVALID_REFRESH_TOKEN");

  if (record.usedAt) {
    await revokeSession(record.sessionId, "refresh_token_reuse");
    logger.warn("refresh_token_reuse_detected", { appId: app.id, sessionId: record.sessionId });
    throw new ApiError("REFRESH_TOKEN_REUSED");
  }
  if (record.session.revokedAt) throw new ApiError("SESSION_REVOKED");
  if (record.expiresAt <= now || record.session.expiresAt <= now) throw new ApiError("REFRESH_TOKEN_EXPIRED");

  const newToken = randomToken("rt_", 32);
  const newExpiresAt = new Date(now.getTime() + getConfig().refreshTokenTtlSeconds * 1000);

  const claimed = await db.$transaction(async (tx) => {
    // Atomic claim: only one concurrent request can flip usedAt from NULL.
    const claim = await tx.refreshToken.updateMany({
      where: { id: record.id, usedAt: null },
      data: { usedAt: now },
    });
    if (claim.count !== 1) return false;
    await tx.refreshToken.create({
      data: { sessionId: record.sessionId, tokenHash: sha256Hex(newToken), expiresAt: newExpiresAt },
    });
    await tx.session.update({
      where: { id: record.sessionId },
      data: { lastUsedAt: now, expiresAt: newExpiresAt },
    });
    return true;
  });

  if (!claimed) {
    // Lost a race with another request using the same token => treat as reuse.
    await revokeSession(record.sessionId, "refresh_token_reuse");
    logger.warn("refresh_token_reuse_detected", { appId: app.id, sessionId: record.sessionId, concurrent: true });
    throw new ApiError("REFRESH_TOKEN_REUSED");
  }

  return issueTokens(app, record.session.userId, record.sessionId, newToken, newExpiresAt);
}

/** Revoke the session a refresh token belongs to (logout). Unknown tokens are ignored. */
export async function revokeByRefreshToken(app: AppRecord, refreshToken: string): Promise<boolean> {
  const record = await getDb().refreshToken.findUnique({
    where: { tokenHash: sha256Hex(refreshToken) },
    include: { session: { select: { appId: true } } },
  });
  if (!record || record.session.appId !== app.id) return false;
  await revokeSession(record.sessionId, "logout");
  return true;
}

export interface ValidatedAccess {
  claims: AccessTokenClaims;
  session: { id: string; createdAt: Date; expiresAt: Date; lastUsedAt: Date };
}

/** Full access-token validation: signature, claims AND live session state (revocation). */
export async function validateAccessToken(app: AppRecord, token: string): Promise<ValidatedAccess> {
  const claims = await verifyAccessToken(app, token);
  const session = await getDb().session.findUnique({ where: { id: claims.session_id } });
  if (
    !session ||
    session.appId !== app.id ||
    session.userId !== claims.sub ||
    session.revokedAt ||
    session.expiresAt <= new Date()
  ) {
    throw new ApiError("SESSION_REVOKED");
  }
  return {
    claims,
    session: { id: session.id, createdAt: session.createdAt, expiresAt: session.expiresAt, lastUsedAt: session.lastUsedAt },
  };
}
