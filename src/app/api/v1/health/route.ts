import { getCounterStore } from "@/lib/rate-limit";
import { getDb } from "@/lib/db";
import { json, route } from "@/lib/http";

/**
 * Liveness + readiness probe for Railway. Not behind the RapidAPI gateway check
 * and reveals no configuration secrets.
 */
export const GET = route(
  async () => {
    const [database, rateLimiter] = await Promise.all([
      getDb()
        .$queryRaw`SELECT 1`
        .then(() => "ok" as const)
        .catch(() => "unavailable" as const),
      (async () => {
        const store = getCounterStore();
        return { store: store.kind, status: (await store.ping()) ? ("ok" as const) : ("unavailable" as const) };
      })().catch(() => ({ store: "unknown", status: "unavailable" as const })),
    ]);
    const healthy = database === "ok" && rateLimiter.status === "ok";
    return json(healthy ? 200 : 503, {
      success: healthy,
      data: {
        status: healthy ? "ok" : "degraded",
        version: "v1",
        checks: {
          database,
          rate_limiter: rateLimiter.status,
          rate_limiter_store: rateLimiter.store,
          ...(rateLimiter.store === "memory" ? { warning: "in-memory rate limiting (single instance, development only)" } : {}),
        },
      },
      error: healthy ? null : { code: "SERVICE_UNAVAILABLE", message: "One or more dependencies are unavailable." },
    });
  },
  { gateway: false },
);
