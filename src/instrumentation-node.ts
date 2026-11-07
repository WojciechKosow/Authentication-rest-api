import { ConfigError, getConfig } from "./lib/config";
import { logger } from "./lib/logger";

/** Node.js-only start-up checks (imported from instrumentation.ts). */
export function validateStartup(): void {
  try {
    const cfg = getConfig();
    logger.info("config_validated", {
      env: cfg.env,
      issuer: cfg.jwtIssuer,
      rateLimiter: cfg.redisUrl ? "redis" : "memory (development only)",
      rapidApiGatewayCheck: Boolean(cfg.rapidApiProxySecret),
      corsOrigins: cfg.corsAllowedOrigins.length,
    });
  } catch (err) {
    if (err instanceof ConfigError) {
      console.error(`[auth-api] FATAL: ${err.message}`);
      process.exit(1);
    }
    throw err;
  }
}
