import { randomUUID } from "node:crypto";
import { errors as joseErrors, jwtVerify, SignJWT } from "jose";
import { AppRecord, jwtSigningKey } from "./apps";
import { getConfig } from "./config";
import { ApiError } from "./errors";

export interface AccessTokenClaims {
  sub: string;
  app_id: string;
  session_id: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string;
  jti: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Issue a short-lived HS256 access token. The key is unique per application
 * (HKDF of JWT_MASTER_SECRET + app_id + key version) and `aud` is the app_id,
 * so a token from one application can never validate for another.
 */
export async function signAccessToken(
  app: Pick<AppRecord, "id" | "jwtKeyVersion">,
  userId: string,
  sessionId: string,
  now: Date = new Date(),
): Promise<{ token: string; expiresAt: Date; claims: AccessTokenClaims }> {
  const { jwtIssuer, accessTokenTtlSeconds } = getConfig();
  const iat = Math.floor(now.getTime() / 1000);
  const exp = iat + accessTokenTtlSeconds;
  const jti = randomUUID();
  const token = await new SignJWT({ app_id: app.id, session_id: sessionId })
    .setProtectedHeader({ alg: "HS256", typ: "JWT", kid: `${app.id}.v${app.jwtKeyVersion}` })
    .setSubject(userId)
    .setIssuer(jwtIssuer)
    .setAudience(app.id)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .setJti(jti)
    .sign(jwtSigningKey(app));
  return {
    token,
    expiresAt: new Date(exp * 1000),
    claims: { sub: userId, app_id: app.id, session_id: sessionId, iat, exp, iss: jwtIssuer, aud: app.id, jti },
  };
}

/** Cryptographically verify an access token for the given application. Does NOT check session state. */
export async function verifyAccessToken(app: Pick<AppRecord, "id" | "jwtKeyVersion">, token: string): Promise<AccessTokenClaims> {
  if (token.length > 4096) throw new ApiError("INVALID_TOKEN");
  try {
    const { payload } = await jwtVerify(token, jwtSigningKey(app), {
      algorithms: ["HS256"],
      issuer: getConfig().jwtIssuer,
      audience: app.id,
      requiredClaims: ["sub", "iat", "exp", "jti"],
      clockTolerance: 5,
    });
    if (
      payload.app_id !== app.id ||
      typeof payload.session_id !== "string" ||
      !UUID.test(payload.session_id) ||
      typeof payload.sub !== "string" ||
      !payload.sub
    ) {
      throw new ApiError("INVALID_TOKEN");
    }
    return payload as unknown as AccessTokenClaims;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    if (err instanceof joseErrors.JWTExpired) throw new ApiError("TOKEN_EXPIRED");
    throw new ApiError("INVALID_TOKEN");
  }
}
