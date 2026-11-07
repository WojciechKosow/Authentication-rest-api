import Redis from "ioredis";
import { getConfig } from "./config";
import { ApiError } from "./errors";
import { logger } from "./logger";

/**
 * Fixed-window rate limiting.
 *
 * - Production: Redis (REDIS_URL) is REQUIRED (enforced by config validation), so
 *   limits are shared by every replica.
 * - Development/test without REDIS_URL: an in-memory store is used. It is only
 *   correct for a single process and is reported as such by /api/v1/health.
 * - If Redis is configured but unreachable, protected endpoints fail CLOSED (503)
 *   instead of silently running without brute-force protection.
 */

export interface CounterStore {
  readonly kind: "redis" | "memory";
  increment(key: string, windowMs: number): Promise<{ count: number; resetInMs: number }>;
  get(key: string): Promise<{ count: number; resetInMs: number }>;
  reset(key: string): Promise<void>;
  ping(): Promise<boolean>;
}

export class MemoryCounterStore implements CounterStore {
  readonly kind = "memory" as const;
  private readonly entries = new Map<string, { count: number; expiresAt: number }>();
  private lastSweep = Date.now();

  private sweep(now: number) {
    if (now - this.lastSweep < 60_000) return;
    this.lastSweep = now;
    for (const [k, v] of this.entries) if (v.expiresAt <= now) this.entries.delete(k);
  }

  async increment(key: string, windowMs: number) {
    const now = Date.now();
    this.sweep(now);
    const current = this.entries.get(key);
    if (!current || current.expiresAt <= now) {
      this.entries.set(key, { count: 1, expiresAt: now + windowMs });
      return { count: 1, resetInMs: windowMs };
    }
    current.count += 1;
    return { count: current.count, resetInMs: current.expiresAt - now };
  }

  async get(key: string) {
    const now = Date.now();
    const current = this.entries.get(key);
    if (!current || current.expiresAt <= now) return { count: 0, resetInMs: 0 };
    return { count: current.count, resetInMs: current.expiresAt - now };
  }

  async reset(key: string) {
    this.entries.delete(key);
  }

  async ping() {
    return true;
  }

  clear() {
    this.entries.clear();
  }
}

const INCR_SCRIPT = `
local c = redis.call('INCR', KEYS[1])
if c == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('PTTL', KEYS[1])
return {c, ttl}
`;

export class RedisCounterStore implements CounterStore {
  readonly kind = "redis" as const;
  constructor(private readonly redis: Redis) {}

  async increment(key: string, windowMs: number) {
    const [count, ttl] = (await this.redis.eval(INCR_SCRIPT, 1, key, String(windowMs))) as [number, number];
    return { count, resetInMs: ttl > 0 ? ttl : windowMs };
  }

  async get(key: string) {
    const [raw, ttl] = await Promise.all([this.redis.get(key), this.redis.pttl(key)]);
    return { count: raw ? Number(raw) : 0, resetInMs: ttl > 0 ? ttl : 0 };
  }

  async reset(key: string) {
    await this.redis.del(key);
  }

  async ping() {
    try {
      return (await this.redis.ping()) === "PONG";
    } catch {
      return false;
    }
  }
}

const globalStore = globalThis as unknown as { __authApiCounterStore?: CounterStore };

export function getCounterStore(): CounterStore {
  if (!globalStore.__authApiCounterStore) {
    const { redisUrl, isProduction } = getConfig();
    if (redisUrl) {
      const redis = new Redis(redisUrl, {
        // family 0 = IPv4 + IPv6 (Railway private networking is IPv6).
        family: 0,
        maxRetriesPerRequest: 1,
        connectTimeout: 3000,
        commandTimeout: 1500,
        enableAutoPipelining: true,
        keyPrefix: "authapi:rl:",
      });
      redis.on("error", (err) => logger.error("redis_error", { error: err.message }));
      globalStore.__authApiCounterStore = new RedisCounterStore(redis);
    } else {
      if (isProduction) {
        // Config validation already prevents this; keep a hard guard anyway.
        throw new Error("REDIS_URL is required in production");
      }
      logger.warn("rate_limiter_memory_fallback", {
        note: "In-memory rate limiting is per-process only. Configure REDIS_URL for shared limits.",
      });
      globalStore.__authApiCounterStore = new MemoryCounterStore();
    }
  }
  return globalStore.__authApiCounterStore;
}

/** Test helper. */
export function setCounterStoreForTests(store: CounterStore | undefined) {
  globalStore.__authApiCounterStore = store;
}

export interface RatePolicy {
  name: string;
  limit: number;
  windowSeconds: number;
}

export const POLICIES = {
  registerPerIp: { name: "register:ip", limit: 10, windowSeconds: 60 * 60 },
  loginPerIp: { name: "login:ip", limit: 30, windowSeconds: 15 * 60 },
  loginFailuresPerAccount: { name: "login:fail", limit: 10, windowSeconds: 15 * 60 },
  refreshPerIp: { name: "refresh:ip", limit: 60, windowSeconds: 15 * 60 },
  emailRequestPerIp: { name: "email:ip", limit: 20, windowSeconds: 60 * 60 },
  emailRequestPerAccount: { name: "email:acct", limit: 5, windowSeconds: 60 * 60 },
  confirmPerIp: { name: "confirm:ip", limit: 30, windowSeconds: 15 * 60 },
} satisfies Record<string, RatePolicy>;

function rateLimited(resetInMs: number): ApiError {
  const retryAfter = Math.max(1, Math.ceil(resetInMs / 1000));
  return new ApiError("RATE_LIMITED", { headers: { "Retry-After": String(retryAfter) } });
}

async function guard<T>(op: () => Promise<T>): Promise<T> {
  try {
    return await op();
  } catch (err) {
    logger.error("rate_limiter_unavailable", { error: err instanceof Error ? err.message : String(err) });
    throw new ApiError("SERVICE_UNAVAILABLE", { cause: err });
  }
}

/** Count this request and reject it when the policy limit is exceeded. */
export async function enforceRateLimit(policy: RatePolicy, key: string): Promise<void> {
  const { count, resetInMs } = await guard(() =>
    getCounterStore().increment(`${policy.name}:${key}`, policy.windowSeconds * 1000),
  );
  if (count > policy.limit) throw rateLimited(resetInMs);
}

/** Reject if the counter is already at/over the limit (without counting this request). */
export async function assertBelowLimit(policy: RatePolicy, key: string): Promise<void> {
  const { count, resetInMs } = await guard(() => getCounterStore().get(`${policy.name}:${key}`));
  if (count >= policy.limit) throw rateLimited(resetInMs);
}

export async function recordHit(policy: RatePolicy, key: string): Promise<void> {
  await guard(() => getCounterStore().increment(`${policy.name}:${key}`, policy.windowSeconds * 1000));
}

export async function resetCounter(policy: RatePolicy, key: string): Promise<void> {
  await guard(() => getCounterStore().reset(`${policy.name}:${key}`));
}
