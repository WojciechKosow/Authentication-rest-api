import { randomUUID } from "node:crypto";
import { Agent, request } from "undici";
import { z } from "zod";
import { AppRecord, integrationSigningSecret } from "./apps";
import { getConfig } from "./config";
import { hmacSha256Hex } from "./crypto";
import { ApiError } from "./errors";
import { logger } from "./logger";
import { ARGON2ID_HASH_PATTERN } from "./password";
import { assertSafeUrl, safeLookup, UnsafeUrlError } from "./ssrf";

/**
 * Client for the Developer Backend Integration Contract (see README).
 *
 * Every request is a POST with a JSON body `{ action, app_id, request_id, data }`
 * signed with HMAC-SHA256:
 *   X-AuthAPI-Signature: v1=hex(HMAC(secret, `${timestamp}.${raw_body}`))
 * The plaintext password is NEVER sent: only Argon2id hashes.
 */

const MAX_RESPONSE_BYTES = 64 * 1024;

export const userIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._:@|-]+$/, "user_id contains unsupported characters");

const emailSchema = z.string().max(254).pipe(z.email());

const createdUserSchema = z.object({ user_id: userIdSchema, email: emailSchema });
const lookupUserSchema = z.object({
  user_id: userIdSchema,
  email: emailSchema,
  password_hash: z.string().max(512).regex(ARGON2ID_HASH_PATTERN, "password_hash must be an Argon2id hash"),
  email_verified: z.boolean().optional(),
});
const profileSchema = z.object({
  user_id: userIdSchema,
  email: emailSchema,
  email_verified: z.boolean().optional(),
});

export type BackendUser = z.infer<typeof profileSchema>;
export type BackendUserWithHash = z.infer<typeof lookupUserSchema>;

let agent: Agent | null = null;
function getAgent(): Agent {
  if (!agent) {
    const { integrationAllowPrivateUrls, integrationTimeoutMs } = getConfig();
    agent = new Agent({
      connect: {
        timeout: Math.min(3000, integrationTimeoutMs),
        // Validate every resolved IP at connect time (prevents DNS rebinding to internal hosts).
        ...(integrationAllowPrivateUrls ? {} : { lookup: safeLookup }),
      },
      headersTimeout: integrationTimeoutMs,
      bodyTimeout: integrationTimeoutMs,
      maxResponseSize: MAX_RESPONSE_BYTES,
      connections: 32,
    });
  }
  return agent;
}

/** Test helper: drop the pooled agent (config may change between test files). */
export async function resetIntegrationAgent(): Promise<void> {
  const a = agent;
  agent = null;
  await a?.close().catch(() => undefined);
}

interface RawResult {
  status: number;
  body: unknown;
}

export function signPayload(secret: string, timestamp: string, rawBody: string): string {
  return `v1=${hmacSha256Hex(secret, `${timestamp}.${rawBody}`)}`;
}

async function post(app: AppRecord, url: string, action: string, data: Record<string, unknown>): Promise<RawResult> {
  const { integrationAllowPrivateUrls, integrationTimeoutMs } = getConfig();
  let target: URL;
  try {
    target = assertSafeUrl(url, integrationAllowPrivateUrls);
  } catch (err) {
    logger.error("integration_url_rejected", { appId: app.id, action, reason: (err as Error).message });
    throw new ApiError("INTEGRATION_ERROR", { cause: err });
  }

  const requestId = randomUUID();
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const rawBody = JSON.stringify({ action, app_id: app.id, request_id: requestId, data });
  const signature = signPayload(integrationSigningSecret(app), timestamp, rawBody);
  const started = Date.now();

  try {
    const res = await request(target, {
      method: "POST",
      dispatcher: getAgent(),
      signal: AbortSignal.timeout(integrationTimeoutMs),
      headers: {
        "content-type": "application/json",
        accept: "application/json",
        "user-agent": "AuthAPI-Integration/1.0",
        "x-authapi-app-id": app.id,
        "x-authapi-action": action,
        "x-authapi-request-id": requestId,
        "x-authapi-timestamp": timestamp,
        "x-authapi-signature": signature,
      },
      body: rawBody,
    });

    const text = await res.body.text();
    let body: unknown = null;
    if (text.length) {
      const contentType = String(res.headers["content-type"] ?? "");
      if (!contentType.includes("application/json")) {
        throw new IntegrationProtocolError(`unexpected content-type '${contentType}' (status ${res.statusCode})`);
      }
      try {
        body = JSON.parse(text);
      } catch {
        throw new IntegrationProtocolError(`invalid JSON (status ${res.statusCode})`);
      }
    }
    logger.debug("integration_call", { appId: app.id, action, status: res.statusCode, durationMs: Date.now() - started });
    return { status: res.statusCode, body };
  } catch (err) {
    const e = err as Error & { code?: string };
    const timedOut =
      e.name === "TimeoutError" ||
      e.name === "AbortError" ||
      e.code === "UND_ERR_HEADERS_TIMEOUT" ||
      e.code === "UND_ERR_BODY_TIMEOUT" ||
      e.code === "UND_ERR_CONNECT_TIMEOUT";
    logger.error("integration_call_failed", {
      appId: app.id,
      action,
      durationMs: Date.now() - started,
      errorName: e.name,
      errorCode: e.code,
      reason: e.message,
    });
    if (err instanceof UnsafeUrlError) throw new ApiError("INTEGRATION_ERROR", { cause: err });
    throw new ApiError(timedOut ? "INTEGRATION_TIMEOUT" : "INTEGRATION_ERROR", { cause: err });
  }
}

class IntegrationProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IntegrationProtocolError";
  }
}

function invalid(app: AppRecord, action: string, status: number, reason: string): ApiError {
  logger.error("integration_invalid_response", { appId: app.id, action, status, reason });
  return new ApiError("INTEGRATION_ERROR");
}

function parse<T extends z.ZodType>(app: AppRecord, action: string, res: RawResult, schema: T): z.infer<T> {
  const result = schema.safeParse(res.body);
  if (!result.success) {
    throw invalid(app, action, res.status, result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
  }
  return result.data;
}

function sameEmail(a: string, b: string) {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/** user.create => 201 {user_id,email} | 409 (already exists) */
export async function backendCreateUser(app: AppRecord, email: string, passwordHash: string): Promise<BackendUser | "exists"> {
  const action = "user.create";
  const res = await post(app, app.backendUrl, action, { email, password_hash: passwordHash });
  if (res.status === 409) return "exists";
  if (res.status !== 200 && res.status !== 201) throw invalid(app, action, res.status, "unexpected status");
  const user = parse(app, action, res, createdUserSchema);
  if (!sameEmail(user.email, email)) throw invalid(app, action, res.status, "email mismatch");
  return { ...user, email_verified: false };
}

/** user.lookup => 200 {user_id,email,password_hash,email_verified?} | 404 */
export async function backendLookupUser(app: AppRecord, email: string): Promise<BackendUserWithHash | null> {
  const action = "user.lookup";
  const res = await post(app, app.backendUrl, action, { email });
  if (res.status === 404) return null;
  if (res.status !== 200) throw invalid(app, action, res.status, "unexpected status");
  const user = parse(app, action, res, lookupUserSchema);
  if (!sameEmail(user.email, email)) throw invalid(app, action, res.status, "email mismatch");
  return user;
}

/** user.get => 200 {user_id,email,email_verified?} | 404 */
export async function backendGetUser(app: AppRecord, userId: string): Promise<BackendUser | null> {
  const action = "user.get";
  const res = await post(app, app.backendUrl, action, { user_id: userId });
  if (res.status === 404) return null;
  if (res.status !== 200) throw invalid(app, action, res.status, "unexpected status");
  const user = parse(app, action, res, profileSchema);
  if (user.user_id !== userId) throw invalid(app, action, res.status, "user_id mismatch");
  return user;
}

/** user.mark_email_verified => 200/204 | 404 */
export async function backendMarkEmailVerified(app: AppRecord, userId: string, email: string): Promise<boolean> {
  const action = "user.mark_email_verified";
  const res = await post(app, app.backendUrl, action, { user_id: userId, email });
  if (res.status === 404) return false;
  if (res.status !== 200 && res.status !== 204) throw invalid(app, action, res.status, "unexpected status");
  return true;
}

/** user.update_password => 200/204 | 404 */
export async function backendUpdatePassword(app: AppRecord, userId: string, passwordHash: string): Promise<boolean> {
  const action = "user.update_password";
  const res = await post(app, app.backendUrl, action, { user_id: userId, password_hash: passwordHash });
  if (res.status === 404) return false;
  if (res.status !== 200 && res.status !== 204) throw invalid(app, action, res.status, "unexpected status");
  return true;
}

/** email.send (to the optional email webhook) => 200/202/204 */
export async function sendEmailWebhook(
  app: AppRecord,
  payload: {
    type: "email_verification" | "password_reset";
    to: string;
    user_id: string;
    token: string;
    expires_at: string;
  },
): Promise<void> {
  if (!app.emailWebhookUrl) throw new ApiError("FEATURE_NOT_CONFIGURED");
  const action = "email.send";
  const res = await post(app, app.emailWebhookUrl, action, payload);
  if (![200, 201, 202, 204].includes(res.status)) throw invalid(app, action, res.status, "unexpected status");
}

export interface PingResult {
  ok: boolean;
  status: number | null;
  latency_ms: number;
  error: string | null;
}

/**
 * app.ping => any 2xx. Used by the self-service "test backend" endpoint so developers can
 * verify reachability and their signature verification before going live.
 */
export async function pingEndpoint(app: AppRecord, url: string): Promise<PingResult> {
  const started = Date.now();
  try {
    const res = await post(app, url, "app.ping", {});
    const ok = res.status >= 200 && res.status < 300;
    let error: string | null = null;
    if (res.status === 401 || res.status === 403) error = "Your endpoint rejected the request: check signature verification and the integration signing secret.";
    else if (res.status >= 300 && res.status < 400) error = "Redirects are not followed: use the final URL.";
    else if (!ok) error = `Your endpoint returned HTTP ${res.status}; app.ping must return 2xx.`;
    return { ok, status: res.status, latency_ms: Date.now() - started, error };
  } catch (err) {
    const code = err instanceof ApiError ? err.code : "INTEGRATION_ERROR";
    return {
      ok: false,
      status: null,
      latency_ms: Date.now() - started,
      error:
        code === "INTEGRATION_TIMEOUT"
          ? "Your endpoint did not respond in time."
          : "Your endpoint could not be reached, is not allowed, or returned a non-JSON body.",
    };
  }
}
