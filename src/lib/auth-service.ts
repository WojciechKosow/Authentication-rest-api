import type { OneTimeTokenPurpose } from "@/generated/prisma/client";
import { AppRecord } from "./apps";
import { randomToken, sha256Hex } from "./crypto";
import { getDb } from "./db";
import { ApiError } from "./errors";
import {
  backendCreateUser,
  backendGetUser,
  backendLookupUser,
  backendMarkEmailVerified,
  backendUpdatePassword,
  sendEmailWebhook,
} from "./integration";
import { logger } from "./logger";
import { hashPassword, verifyAgainstDummy, verifyPassword } from "./password";
import { assertBelowLimit, enforceRateLimit, POLICIES, recordHit, resetCounter } from "./rate-limit";
import {
  createSession,
  revokeAllUserSessions,
  revokeByRefreshToken,
  revokeSession,
  rotateRefreshToken,
  validateAccessToken,
} from "./sessions";

const k = (app: AppRecord, part: string) => `${app.id}:${part}`;

export async function register(app: AppRecord, ip: string, email: string, password: string) {
  await enforceRateLimit(POLICIES.registerPerIp, k(app, ip));
  const passwordHash = await hashPassword(password);
  const created = await backendCreateUser(app, email, passwordHash);
  if (created === "exists") throw new ApiError("EMAIL_ALREADY_REGISTERED");
  const tokens = await createSession(app, created.user_id);
  logger.info("user_registered", { appId: app.id, userId: created.user_id });
  return { user: created, tokens };
}

export async function login(app: AppRecord, ip: string, email: string, password: string) {
  await enforceRateLimit(POLICIES.loginPerIp, k(app, ip));
  const accountKey = k(app, sha256Hex(email));
  // Brute-force protection per account (applies equally to unknown emails => no enumeration).
  await assertBelowLimit(POLICIES.loginFailuresPerAccount, accountKey);

  const user = await backendLookupUser(app, email);
  let valid = false;
  if (user) valid = await verifyPassword(user.password_hash, password);
  else await verifyAgainstDummy(password);

  if (!user || !valid) {
    await recordHit(POLICIES.loginFailuresPerAccount, accountKey);
    throw new ApiError("INVALID_CREDENTIALS");
  }

  await resetCounter(POLICIES.loginFailuresPerAccount, accountKey);
  const tokens = await createSession(app, user.user_id);
  return {
    user: { user_id: user.user_id, email: user.email, email_verified: user.email_verified ?? null },
    tokens,
  };
}

export async function refresh(app: AppRecord, ip: string, refreshToken: string) {
  await enforceRateLimit(POLICIES.refreshPerIp, k(app, ip));
  return { tokens: await rotateRefreshToken(app, refreshToken) };
}

export async function logout(
  app: AppRecord,
  input: { accessToken: string | null; refreshToken?: string; allSessions?: boolean },
) {
  if (!input.accessToken && !input.refreshToken) {
    throw new ApiError("VALIDATION_ERROR", {
      details: [{ path: "(body)", message: "Provide refresh_token in the body and/or a Bearer access token" }],
    });
  }
  if (input.accessToken) {
    const { claims } = await validateAccessToken(app, input.accessToken);
    if (input.allSessions) await revokeAllUserSessions(app.id, claims.sub, "logout_all");
    else await revokeSession(claims.session_id, "logout");
  } else if (input.allSessions) {
    throw new ApiError("VALIDATION_ERROR", {
      details: [{ path: "all_sessions", message: "all_sessions requires a Bearer access token" }],
    });
  }
  // Unknown refresh tokens are ignored: logout is idempotent and reveals nothing.
  if (input.refreshToken) await revokeByRefreshToken(app, input.refreshToken);
  return { logged_out: true };
}

export async function validate(app: AppRecord, accessToken: string) {
  const { claims, session } = await validateAccessToken(app, accessToken);
  return {
    active: true,
    user_id: claims.sub,
    app_id: claims.app_id,
    session_id: claims.session_id,
    issued_at: new Date(claims.iat * 1000).toISOString(),
    expires_at: new Date(claims.exp * 1000).toISOString(),
    session_expires_at: session.expiresAt.toISOString(),
  };
}

export async function me(app: AppRecord, accessToken: string) {
  const { claims, session } = await validateAccessToken(app, accessToken);
  const user = await backendGetUser(app, claims.sub);
  if (!user) {
    // The developer deleted the user: their sessions must stop working.
    await revokeAllUserSessions(app.id, claims.sub, "user_deleted");
    throw new ApiError("SESSION_REVOKED");
  }
  return {
    user: { user_id: user.user_id, email: user.email, email_verified: user.email_verified ?? null },
    session: {
      session_id: session.id,
      created_at: session.createdAt.toISOString(),
      expires_at: session.expiresAt.toISOString(),
      access_token_expires_at: new Date(claims.exp * 1000).toISOString(),
    },
  };
}

// ---------------------------------------------------------------------------
// Optional email flows (require Application.emailWebhookUrl)
// ---------------------------------------------------------------------------

const ONE_TIME = {
  EMAIL_VERIFICATION: { prefix: "ev_", ttlMs: 24 * 60 * 60 * 1000, type: "email_verification" as const },
  PASSWORD_RESET: { prefix: "pr_", ttlMs: 60 * 60 * 1000, type: "password_reset" as const },
} satisfies Record<OneTimeTokenPurpose, unknown>;

/** Generic response for request endpoints: never reveals whether the email is registered. */
const ACCEPTED = { accepted: true };

async function requestOneTimeToken(app: AppRecord, ip: string, email: string, purpose: OneTimeTokenPurpose) {
  if (!app.emailWebhookUrl) throw new ApiError("FEATURE_NOT_CONFIGURED");
  await enforceRateLimit(POLICIES.emailRequestPerIp, k(app, ip));
  await enforceRateLimit(POLICIES.emailRequestPerAccount, k(app, `${purpose}:${sha256Hex(email)}`));

  const user = await backendLookupUser(app, email);
  if (!user) return ACCEPTED;
  if (purpose === "EMAIL_VERIFICATION" && user.email_verified === true) return ACCEPTED;

  const cfg = ONE_TIME[purpose];
  const token = randomToken(cfg.prefix, 32);
  const expiresAt = new Date(Date.now() + cfg.ttlMs);
  const db = getDb();
  await db.$transaction([
    // Only the newest token of a given purpose stays valid.
    db.oneTimeToken.updateMany({
      where: { appId: app.id, userId: user.user_id, purpose, usedAt: null },
      data: { usedAt: new Date() },
    }),
    db.oneTimeToken.create({
      data: { appId: app.id, userId: user.user_id, email: user.email, purpose, tokenHash: sha256Hex(token), expiresAt },
    }),
  ]);

  try {
    await sendEmailWebhook(app, {
      type: cfg.type,
      to: user.email,
      user_id: user.user_id,
      token,
      expires_at: expiresAt.toISOString(),
    });
  } catch (err) {
    // Do not reveal (via a different response) that the account exists; the failure is logged.
    logger.error("email_webhook_failed", { appId: app.id, purpose, code: err instanceof ApiError ? err.code : "UNKNOWN" });
  }
  return ACCEPTED;
}

/** Atomically consume a one-time token. Returns null if invalid/expired/used. */
async function consumeOneTimeToken(app: AppRecord, token: string, purpose: OneTimeTokenPurpose) {
  const db = getDb();
  const record = await db.oneTimeToken.findUnique({ where: { tokenHash: sha256Hex(token) } });
  if (!record || record.appId !== app.id || record.purpose !== purpose) return null;
  const now = new Date();
  const claim = await db.oneTimeToken.updateMany({
    where: { id: record.id, usedAt: null, expiresAt: { gt: now } },
    data: { usedAt: now },
  });
  return claim.count === 1 ? record : null;
}

async function releaseOneTimeToken(id: string) {
  // The backend call failed: let the user retry with the same (still unexpired) token.
  await getDb().oneTimeToken.updateMany({ where: { id }, data: { usedAt: null } });
}

export function requestEmailVerification(app: AppRecord, ip: string, email: string) {
  return requestOneTimeToken(app, ip, email, "EMAIL_VERIFICATION");
}

export function requestPasswordReset(app: AppRecord, ip: string, email: string) {
  return requestOneTimeToken(app, ip, email, "PASSWORD_RESET");
}

export async function confirmEmailVerification(app: AppRecord, ip: string, token: string) {
  if (!app.emailWebhookUrl) throw new ApiError("FEATURE_NOT_CONFIGURED");
  await enforceRateLimit(POLICIES.confirmPerIp, k(app, ip));
  const record = await consumeOneTimeToken(app, token, "EMAIL_VERIFICATION");
  if (!record) throw new ApiError("INVALID_ONE_TIME_TOKEN");
  let updated: boolean;
  try {
    updated = await backendMarkEmailVerified(app, record.userId, record.email);
  } catch (err) {
    await releaseOneTimeToken(record.id);
    throw err;
  }
  if (!updated) throw new ApiError("INVALID_ONE_TIME_TOKEN");
  return { user_id: record.userId, email: record.email, email_verified: true };
}

export async function confirmPasswordReset(app: AppRecord, ip: string, token: string, newPassword: string) {
  if (!app.emailWebhookUrl) throw new ApiError("FEATURE_NOT_CONFIGURED");
  await enforceRateLimit(POLICIES.confirmPerIp, k(app, ip));
  const record = await consumeOneTimeToken(app, token, "PASSWORD_RESET");
  if (!record) throw new ApiError("INVALID_ONE_TIME_TOKEN");
  const passwordHash = await hashPassword(newPassword);
  let updated: boolean;
  try {
    updated = await backendUpdatePassword(app, record.userId, passwordHash);
  } catch (err) {
    await releaseOneTimeToken(record.id);
    throw err;
  }
  if (!updated) throw new ApiError("INVALID_ONE_TIME_TOKEN");
  // A password reset signs the user out everywhere and clears the lockout counter.
  const revoked = await revokeAllUserSessions(app.id, record.userId, "password_reset");
  await resetCounter(POLICIES.loginFailuresPerAccount, k(app, sha256Hex(record.email)));
  return { password_reset: true, sessions_revoked: revoked };
}
