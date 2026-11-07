/**
 * Every error returned by the API has a stable machine-readable `code`.
 * The table below is the single source of truth (also documented in README/OpenAPI).
 */
export const ERRORS = {
  VALIDATION_ERROR: { status: 400, message: "The request body is invalid." },
  INVALID_JSON: { status: 400, message: "The request body must be valid JSON." },
  UNSUPPORTED_MEDIA_TYPE: { status: 415, message: "Content-Type must be application/json." },
  PAYLOAD_TOO_LARGE: { status: 413, message: "The request body is too large." },
  PROXY_AUTH_FAILED: { status: 403, message: "Requests must come through the API gateway." },
  MISSING_APP_CREDENTIALS: { status: 401, message: "X-App-Id and X-App-Secret headers are required." },
  INVALID_APP_CREDENTIALS: { status: 401, message: "Invalid application credentials." },
  APP_ACCESS_DENIED: { status: 403, message: "This application cannot be used with the current subscription." },
  INVALID_CREDENTIALS: { status: 401, message: "Invalid email or password." },
  EMAIL_ALREADY_REGISTERED: { status: 409, message: "An account with this email already exists." },
  MISSING_ACCESS_TOKEN: { status: 401, message: "A Bearer access token is required." },
  INVALID_TOKEN: { status: 401, message: "The access token is invalid." },
  TOKEN_EXPIRED: { status: 401, message: "The access token has expired." },
  SESSION_REVOKED: { status: 401, message: "The session has been revoked or has expired." },
  INVALID_REFRESH_TOKEN: { status: 401, message: "The refresh token is invalid." },
  REFRESH_TOKEN_EXPIRED: { status: 401, message: "The refresh token has expired." },
  REFRESH_TOKEN_REUSED: {
    status: 401,
    message: "The refresh token was already used. The session has been revoked for safety.",
  },
  INVALID_ONE_TIME_TOKEN: { status: 400, message: "The token is invalid, expired or already used." },
  FEATURE_NOT_CONFIGURED: { status: 501, message: "This feature is not configured for the application." },
  RATE_LIMITED: { status: 429, message: "Too many requests. Please try again later." },
  NOT_FOUND: { status: 404, message: "The requested resource does not exist." },
  INTEGRATION_ERROR: { status: 502, message: "The application backend returned an invalid response." },
  INTEGRATION_TIMEOUT: { status: 504, message: "The application backend did not respond in time." },
  SERVICE_UNAVAILABLE: { status: 503, message: "The service is temporarily unavailable." },
  INTERNAL_ERROR: { status: 500, message: "An unexpected error occurred." },
} as const;

export type ErrorCode = keyof typeof ERRORS;

export interface ErrorDetail {
  path: string;
  message: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly details?: ErrorDetail[];
  readonly headers?: Record<string, string>;
  constructor(
    public readonly code: ErrorCode,
    options: { message?: string; details?: ErrorDetail[]; headers?: Record<string, string>; cause?: unknown } = {},
  ) {
    super(options.message ?? ERRORS[code].message, { cause: options.cause });
    this.name = "ApiError";
    this.status = ERRORS[code].status;
    this.details = options.details;
    this.headers = options.headers;
  }
}
