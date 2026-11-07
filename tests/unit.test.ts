import Redis from "ioredis";
import { describe, expect, it } from "vitest";
import { parseConfig } from "@/lib/config";
import { redact } from "@/lib/logger";
import { RedisCounterStore } from "@/lib/rate-limit";
import { assertSafeUrl, isPublicIp, safeLookup } from "@/lib/ssrf";
import { TEST_ENV } from "./test-env";

describe("SSRF protection", () => {
  it.each([
    "127.0.0.1",
    "10.1.2.3",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "0.0.0.0",
    "::1",
    "::",
    "fc00::1",
    "fe80::1",
    "::ffff:127.0.0.1",
    "::ffff:7f00:1",
    "::ffff:a9fe:a9fe",
  ])("treats %s as non-public", (ip) => {
    expect(isPublicIp(ip)).toBe(false);
  });

  it.each(["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])("treats %s as public", (ip) => {
    expect(isPublicIp(ip)).toBe(true);
  });

  it.each([
    "http://api.example.com/hook",
    "https://user:pass@api.example.com/hook",
    "https://localhost/hook",
    "https://127.0.0.1/hook",
    "https://[::1]/hook",
    "https://2130706433/hook",
    "https://169.254.169.254/latest/meta-data",
    "https://postgres.railway.internal/hook",
    "https://intranet/hook",
    "ftp://example.com/",
    "not a url",
  ])("rejects unsafe URL %s", (url) => {
    expect(() => assertSafeUrl(url, false)).toThrow();
  });

  it("accepts public https URLs", () => {
    expect(assertSafeUrl("https://api.example.com/auth-hook", false).hostname).toBe("api.example.com");
  });

  it("blocks connections to hostnames resolving to private addresses (DNS rebinding)", async () => {
    const err = await new Promise<NodeJS.ErrnoException | null>((resolve) =>
      safeLookup("localhost", { all: true }, (e) => resolve(e)),
    );
    expect(err?.code).toBe("ESSRFBLOCKED");
  });
});

describe("configuration validation", () => {
  const base = { ...TEST_ENV, INTEGRATION_ALLOW_PRIVATE_URLS: "" };

  it("accepts a valid development config", () => {
    expect(parseConfig(base).accessTokenTtlSeconds).toBe(900);
  });

  it("rejects weak or placeholder secrets", () => {
    expect(() => parseConfig({ ...base, JWT_MASTER_SECRET: "short" })).toThrow(/JWT_MASTER_SECRET/);
    expect(() => parseConfig({ ...base, JWT_MASTER_SECRET: "change-me-change-me-change-me-change-me" })).toThrow(/placeholder/);
    expect(() => parseConfig({ ...base, INTEGRATION_MASTER_SECRET: TEST_ENV.JWT_MASTER_SECRET })).toThrow(/different/);
  });

  it("requires Redis, RapidAPI proxy secret and an https issuer in production", () => {
    const prod = { ...base, NODE_ENV: "production" };
    expect(() => parseConfig(prod)).toThrow(/REDIS_URL/);
    expect(() => parseConfig(prod)).toThrow(/RAPIDAPI_PROXY_SECRET/);
    expect(() =>
      parseConfig({ ...prod, REDIS_URL: "redis://x", RAPIDAPI_PROXY_SECRET: "x".repeat(32), JWT_ISSUER: "http://a.com" }),
    ).toThrow(/https/);
    expect(() =>
      parseConfig({
        ...prod,
        REDIS_URL: "redis://x",
        RAPIDAPI_PROXY_SECRET: "x".repeat(32),
        INTEGRATION_ALLOW_PRIVATE_URLS: "true",
      }),
    ).toThrow(/INTEGRATION_ALLOW_PRIVATE_URLS/);
    const ok = parseConfig({ ...prod, REDIS_URL: "redis://x", RAPIDAPI_PROXY_SECRET: "x".repeat(32) });
    expect(ok.isProduction).toBe(true);
  });

  it("rejects wildcard CORS", () => {
    expect(() => parseConfig({ ...base, CORS_ALLOWED_ORIGINS: "*" })).toThrow(/CORS/);
  });
});

describe("log redaction", () => {
  it("redacts sensitive fields recursively", () => {
    expect(
      redact({ email: "a@b.co", password: "x", nested: { refresh_token: "y", appSecret: "z", ok: 1 }, authorization: "Bearer" }),
    ).toEqual({ email: "a@b.co", password: "[redacted]", nested: { refresh_token: "[redacted]", appSecret: "[redacted]", ok: 1 }, authorization: "[redacted]" });
  });
});

const REDIS_URL = process.env.TEST_REDIS_URL ?? "redis://127.0.0.1:6379";

describe("Redis rate-limit store", () => {
  it("counts within a shared window", async () => {
    const redis = new Redis(REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 0, keyPrefix: "authapi:test:" });
    try {
      await redis.connect();
    } catch {
      console.warn(`Redis not reachable at ${REDIS_URL}; skipping Redis store test`);
      redis.disconnect();
      return;
    }
    const store = new RedisCounterStore(redis);
    const key = `k${Date.now()}`;
    expect((await store.increment(key, 5000)).count).toBe(1);
    expect((await store.increment(key, 5000)).count).toBe(2);
    const state = await store.get(key);
    expect(state.count).toBe(2);
    expect(state.resetInMs).toBeGreaterThan(0);
    await store.reset(key);
    expect((await store.get(key)).count).toBe(0);
    expect(await store.ping()).toBe(true);
    redis.disconnect();
  });
});
