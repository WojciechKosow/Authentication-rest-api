import { z } from "zod";

/**
 * Central, validated configuration. Parsed lazily (first use) so that
 * `next build` does not need production secrets, and eagerly at server
 * start-up from `src/instrumentation.ts` so a misconfigured deployment
 * fails fast instead of serving insecure traffic.
 */

const PLACEHOLDER_PATTERN = /change[-_ ]?me|example|placeholder|secret123|your[-_]/i;

const strongSecret = (name: string) =>
  z
    .string({ error: `${name} is required` })
    .min(32, `${name} must be at least 32 characters (use: openssl rand -base64 48)`)
    .refine((v) => !PLACEHOLDER_PATTERN.test(v), `${name} looks like a placeholder value`)
    .refine((v) => new Set(v).size >= 10, `${name} has too little entropy`);

const boolFromEnv = z
  .enum(["true", "false", "1", "0", ""])
  .optional()
  .transform((v) => v === "true" || v === "1");

const intFromEnv = (def: number, min: number, max: number) =>
  z.coerce.number().int().min(min).max(max).default(def);

const EnvSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
  JWT_MASTER_SECRET: strongSecret("JWT_MASTER_SECRET"),
  INTEGRATION_MASTER_SECRET: strongSecret("INTEGRATION_MASTER_SECRET"),
  JWT_ISSUER: z.string().url().optional(),
  ACCESS_TOKEN_TTL_SECONDS: intFromEnv(900, 60, 3600),
  REFRESH_TOKEN_TTL_DAYS: intFromEnv(30, 1, 365),
  REDIS_URL: z.string().optional(),
  RAPIDAPI_PROXY_SECRET: z.string().optional(),
  CORS_ALLOWED_ORIGINS: z.string().optional(),
  INTEGRATION_TIMEOUT_MS: intFromEnv(5000, 500, 15000),
  INTEGRATION_ALLOW_PRIVATE_URLS: boolFromEnv,
  LOG_LEVEL: z.enum(["debug", "info", "warn", "error", "silent"]).default("info"),
});

export interface AppConfig {
  env: "development" | "test" | "production";
  isProduction: boolean;
  databaseUrl: string;
  jwtMasterSecret: string;
  integrationMasterSecret: string;
  jwtIssuer: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
  redisUrl: string | null;
  rapidApiProxySecret: string | null;
  corsAllowedOrigins: string[];
  integrationTimeoutMs: number;
  /** DEV/TEST ONLY: allow http:// and private-network integration URLs. Rejected in production. */
  integrationAllowPrivateUrls: boolean;
  logLevel: "debug" | "info" | "warn" | "error" | "silent";
}

export class ConfigError extends Error {
  constructor(public readonly issues: string[]) {
    super(`Invalid configuration:\n  - ${issues.join("\n  - ")}`);
    this.name = "ConfigError";
  }
}

export function parseConfig(env: Record<string, string | undefined>): AppConfig {
  const parsed = EnvSchema.safeParse(env);
  if (!parsed.success) {
    throw new ConfigError(
      parsed.error.issues.map((i) => `${i.path.join(".") || "env"}: ${i.message}`),
    );
  }
  const e = parsed.data;
  const isProduction = e.NODE_ENV === "production";
  const issues: string[] = [];

  if (e.JWT_MASTER_SECRET === e.INTEGRATION_MASTER_SECRET) {
    issues.push("JWT_MASTER_SECRET and INTEGRATION_MASTER_SECRET must be different");
  }

  if (isProduction) {
    if (!e.JWT_ISSUER) issues.push("JWT_ISSUER is required in production (e.g. https://auth.example.com)");
    else if (!e.JWT_ISSUER.startsWith("https://")) issues.push("JWT_ISSUER must use https:// in production");
    if (!e.REDIS_URL) {
      issues.push(
        "REDIS_URL is required in production: rate limiting must use a shared store (the in-memory limiter is for local development only)",
      );
    }
    if (!e.RAPIDAPI_PROXY_SECRET) {
      issues.push("RAPIDAPI_PROXY_SECRET is required in production (RapidAPI Studio > Gateway > Proxy Secret)");
    } else if (e.RAPIDAPI_PROXY_SECRET.length < 16) {
      issues.push("RAPIDAPI_PROXY_SECRET looks too short");
    }
    if (e.INTEGRATION_ALLOW_PRIVATE_URLS) {
      issues.push("INTEGRATION_ALLOW_PRIVATE_URLS must not be enabled in production (SSRF protection)");
    }
  }

  const corsAllowedOrigins = (e.CORS_ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
  for (const origin of corsAllowedOrigins) {
    if (origin === "*") issues.push("CORS_ALLOWED_ORIGINS must not contain '*'");
    else if (!/^https?:\/\/[^/\s]+$/.test(origin)) issues.push(`CORS_ALLOWED_ORIGINS entry is not an origin: ${origin}`);
  }

  if (issues.length) throw new ConfigError(issues);

  return {
    env: e.NODE_ENV,
    isProduction,
    databaseUrl: e.DATABASE_URL,
    jwtMasterSecret: e.JWT_MASTER_SECRET,
    integrationMasterSecret: e.INTEGRATION_MASTER_SECRET,
    jwtIssuer: (e.JWT_ISSUER ?? "http://localhost:3000").replace(/\/$/, ""),
    accessTokenTtlSeconds: e.ACCESS_TOKEN_TTL_SECONDS,
    refreshTokenTtlSeconds: e.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60,
    redisUrl: e.REDIS_URL || null,
    rapidApiProxySecret: e.RAPIDAPI_PROXY_SECRET || null,
    corsAllowedOrigins,
    integrationTimeoutMs: e.INTEGRATION_TIMEOUT_MS,
    integrationAllowPrivateUrls: e.INTEGRATION_ALLOW_PRIVATE_URLS,
    logLevel: e.LOG_LEVEL,
  };
}

let cached: AppConfig | null = null;

export function getConfig(): AppConfig {
  if (!cached) cached = parseConfig(process.env);
  return cached;
}

/** Test helper: force re-reading process.env. */
export function resetConfigForTests(): void {
  cached = null;
}
