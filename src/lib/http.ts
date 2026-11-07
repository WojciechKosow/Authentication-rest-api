import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { z } from "zod";
import { getConfig } from "./config";
import { safeEqual } from "./crypto";
import { ApiError, ErrorDetail } from "./errors";
import { logger } from "./logger";

export const MAX_BODY_BYTES = 16 * 1024;

const SECURITY_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  Pragma: "no-cache",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Resource-Policy": "same-origin",
};

export interface RequestContext {
  requestId: string;
  /** Best-effort client IP, used only as a rate-limit key (always namespaced per app). */
  clientIp: string;
  /** Dynamic route segments (e.g. { appId: "app_..." }). */
  params: Record<string, string | string[] | undefined>;
}

/** Shape of the second argument Next.js passes to route handlers. */
export interface RouteContextArg {
  params: Promise<Record<string, string | string[] | undefined>>;
}

export function json(
  status: number,
  body: { success: boolean; data: unknown; error: unknown },
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS, ...extraHeaders },
  });
}

export function ok(data: unknown, status = 200): Response {
  return json(status, { success: true, data, error: null });
}

export function errorResponse(err: ApiError): Response {
  const error: { code: string; message: string; details?: ErrorDetail[] } = { code: err.code, message: err.message };
  if (err.details?.length) error.details = err.details;
  return json(err.status, { success: false, data: null, error }, err.headers ?? {});
}

/** Read and parse a JSON body with a hard byte limit, then validate it with Zod. */
export async function readJson<T extends z.ZodType>(request: Request, schema: T): Promise<z.infer<T>> {
  const contentType = request.headers.get("content-type") ?? "";
  if (!/^application\/json\b/i.test(contentType)) throw new ApiError("UNSUPPORTED_MEDIA_TYPE");

  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > MAX_BODY_BYTES) throw new ApiError("PAYLOAD_TOO_LARGE");

  let raw = "";
  if (request.body) {
    const reader = request.body.getReader();
    const decoder = new TextDecoder();
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new ApiError("PAYLOAD_TOO_LARGE");
      }
      raw += decoder.decode(value, { stream: true });
    }
    raw += decoder.decode();
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ApiError("INVALID_JSON");
  }

  const result = schema.safeParse(parsed);
  if (!result.success) {
    throw new ApiError("VALIDATION_ERROR", {
      details: result.error.issues.slice(0, 20).map((i) => ({
        path: i.path.join(".") || "(body)",
        message: i.message,
      })),
    });
  }
  return result.data;
}

export function getBearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header) return null;
  const match = /^Bearer\s+([A-Za-z0-9\-_.]+)$/i.exec(header.trim());
  return match ? match[1] : null;
}

function resolveClientIp(request: Request): string {
  // Developer backends usually call us on behalf of their end users, so they may
  // forward the end-user IP. The value is only used as a per-app rate-limit key.
  const candidates = [
    request.headers.get("x-end-user-ip"),
    request.headers.get("x-forwarded-for")?.split(",")[0],
    request.headers.get("x-real-ip"),
  ];
  for (const c of candidates) {
    const v = c?.trim();
    if (v && isIP(v)) return v;
  }
  return "unknown";
}

function corsHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get("origin");
  const allowed = getConfig().corsAllowedOrigins;
  if (!origin || !allowed.includes(origin)) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    Vary: "Origin",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-App-Id, X-App-Secret, X-End-User-IP",
    "Access-Control-Max-Age": "600",
  };
}

/** CORS preflight handler. Origins not in CORS_ALLOWED_ORIGINS get no CORS headers. */
export function preflight(request: Request): Response {
  const headers = corsHeaders(request);
  return new Response(null, { status: Object.keys(headers).length ? 204 : 403, headers: { ...SECURITY_HEADERS, ...headers } });
}

function verifyGateway(request: Request): void {
  const expected = getConfig().rapidApiProxySecret;
  if (!expected) return; // not configured (local development); config validation requires it in production
  const provided = request.headers.get("x-rapidapi-proxy-secret");
  if (!provided || !safeEqual(provided, expected)) throw new ApiError("PROXY_AUTH_FAILED");
}

type Handler = (request: Request, ctx: RequestContext) => Promise<Response>;

/**
 * Wraps every route handler: request id, gateway (RapidAPI) verification,
 * CORS, security headers, consistent error envelope and safe access logging.
 */
export function route(handler: Handler, options: { gateway?: boolean } = {}) {
  const requireGateway = options.gateway ?? true;
  return async function wrapped(request: Request, routeContext?: RouteContextArg): Promise<Response> {
    const started = Date.now();
    const requestId = randomUUID();
    const path = new URL(request.url).pathname;
    let response: Response;
    let errorCode: string | undefined;
    try {
      if (requireGateway) verifyGateway(request);
      const params = (await routeContext?.params) ?? {};
      response = await handler(request, { requestId, clientIp: resolveClientIp(request), params });
    } catch (err) {
      if (err instanceof ApiError) {
        errorCode = err.code;
        if (err.status >= 500) logger.error("request_failed", { requestId, path, code: err.code, cause: describe(err.cause) });
        response = errorResponse(err);
      } else {
        errorCode = "INTERNAL_ERROR";
        logger.error("unhandled_error", { requestId, path, error: describe(err) });
        response = errorResponse(new ApiError("INTERNAL_ERROR"));
      }
    }
    response.headers.set("X-Request-Id", requestId);
    for (const [k, v] of Object.entries(corsHeaders(request))) response.headers.set(k, v);
    logger.info("request", {
      requestId,
      method: request.method,
      path,
      status: response.status,
      durationMs: Date.now() - started,
      errorCode,
    });
    return response;
  };
}

function describe(err: unknown): unknown {
  if (!err) return undefined;
  if (err instanceof Error) return { name: err.name, message: err.message };
  return String(err);
}
