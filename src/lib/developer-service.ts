import { AppRecord, generateAppId, generateAppSecret, hashAppSecret, integrationSigningSecret, APP_ID_PATTERN } from "./apps";
import { getConfig } from "./config";
import { getDb } from "./db";
import { ApiError } from "./errors";
import { pingEndpoint } from "./integration";
import { logger } from "./logger";
import { enforceRateLimit, RatePolicy } from "./rate-limit";
import { UnsafeUrlError, validateIntegrationUrl } from "./ssrf";

/**
 * Self-service application management for RapidAPI subscribers.
 *
 * This is NOT a public registration endpoint: the developer identity is the
 * `X-RapidAPI-User` header, which is only trusted because every request has
 * already passed the `X-RapidAPI-Proxy-Secret` check (i.e. it really came
 * through the RapidAPI gateway for a subscribed, authenticated consumer).
 * Every application created here is bound to that RapidAPI user, so its
 * credentials only work from the owner's subscription.
 */

const DEVELOPER_PATTERN = /^[A-Za-z0-9._@+-]{1,100}$/;

const POLICIES = {
  create: { name: "apps:create", limit: 10, windowSeconds: 60 * 60 },
  manage: { name: "apps:manage", limit: 120, windowSeconds: 60 * 60 },
  test: { name: "apps:test", limit: 30, windowSeconds: 60 * 60 },
} satisfies Record<string, RatePolicy>;

export interface Developer {
  rapidApiUser: string;
}

export function authenticateDeveloper(request: Request): Developer {
  // Without a configured gateway secret the X-RapidAPI-User header could be forged by anyone.
  if (!getConfig().rapidApiProxySecret) {
    throw new ApiError("PROXY_AUTH_FAILED", {
      message: "Application management is only available through the RapidAPI gateway.",
    });
  }
  const user = request.headers.get("x-rapidapi-user")?.trim();
  if (!user || !DEVELOPER_PATTERN.test(user)) throw new ApiError("MISSING_DEVELOPER_IDENTITY");
  return { rapidApiUser: user };
}

export function publicApp(app: AppRecord) {
  return {
    app_id: app.id,
    name: app.name,
    backend_url: app.backendUrl,
    email_webhook_url: app.emailWebhookUrl,
    is_active: app.isActive,
    integration_secret_version: app.integrationSecretVersion,
    created_at: app.createdAt.toISOString(),
    updated_at: app.updatedAt.toISOString(),
  };
}

function ownHosts(): string[] {
  const hosts = ["rapidapi.com"];
  try {
    hosts.push(new URL(getConfig().jwtIssuer).hostname.toLowerCase());
  } catch {
    /* issuer validated by config */
  }
  return hosts;
}

async function checkUrl(field: string, raw: string): Promise<string> {
  try {
    return await validateIntegrationUrl(raw, { allowPrivate: getConfig().integrationAllowPrivateUrls, ownHosts: ownHosts() });
  } catch (err) {
    if (err instanceof UnsafeUrlError) {
      throw new ApiError("INVALID_INTEGRATION_URL", { details: [{ path: field, message: err.message }] });
    }
    throw err;
  }
}

async function findOwned(dev: Developer, appId: string | string[] | undefined): Promise<AppRecord> {
  // Unknown and foreign apps are indistinguishable (404), so app IDs cannot be probed.
  if (typeof appId !== "string" || !APP_ID_PATTERN.test(appId)) throw new ApiError("NOT_FOUND");
  const app = await getDb().application.findUnique({ where: { id: appId } });
  if (!app || app.rapidApiUser !== dev.rapidApiUser) throw new ApiError("NOT_FOUND");
  return app;
}

export async function createApp(
  dev: Developer,
  input: { name: string; backend_url: string; email_webhook_url?: string | null },
) {
  await enforceRateLimit(POLICIES.create, dev.rapidApiUser);
  const backendUrl = await checkUrl("backend_url", input.backend_url);
  const emailWebhookUrl = input.email_webhook_url ? await checkUrl("email_webhook_url", input.email_webhook_url) : null;
  const appSecret = generateAppSecret();
  const max = getConfig().maxAppsPerDeveloper;

  const app = await getDb().$transaction(async (tx) => {
    // Serialize creations per developer so the limit cannot be raced.
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`apps:${dev.rapidApiUser}`}))`;
    const count = await tx.application.count({ where: { rapidApiUser: dev.rapidApiUser } });
    if (count >= max) throw new ApiError("APP_LIMIT_REACHED", { message: `You can create at most ${max} applications.` });
    return tx.application.create({
      data: {
        id: generateAppId(),
        name: input.name,
        secretHash: hashAppSecret(appSecret),
        backendUrl,
        emailWebhookUrl,
        rapidApiUser: dev.rapidApiUser,
      },
    });
  });

  logger.info("app_created", { appId: app.id, developer: dev.rapidApiUser });
  return {
    app: publicApp(app),
    credentials: {
      app_secret: appSecret,
      integration_signing_secret: integrationSigningSecret(app),
      note: "Store these secrets now. They are shown only once; use the rotate endpoints to replace them.",
    },
  };
}

export async function listApps(dev: Developer) {
  await enforceRateLimit(POLICIES.manage, dev.rapidApiUser);
  const apps = await getDb().application.findMany({
    where: { rapidApiUser: dev.rapidApiUser },
    orderBy: { createdAt: "asc" },
  });
  return { apps: apps.map(publicApp), limit: getConfig().maxAppsPerDeveloper };
}

export async function getApp(dev: Developer, appId: string | string[] | undefined) {
  await enforceRateLimit(POLICIES.manage, dev.rapidApiUser);
  return { app: publicApp(await findOwned(dev, appId)) };
}

export async function updateApp(
  dev: Developer,
  appId: string | string[] | undefined,
  input: { name?: string; backend_url?: string; email_webhook_url?: string | null },
) {
  await enforceRateLimit(POLICIES.manage, dev.rapidApiUser);
  const app = await findOwned(dev, appId);
  const data: { name?: string; backendUrl?: string; emailWebhookUrl?: string | null } = {};
  if (input.name !== undefined) data.name = input.name;
  if (input.backend_url !== undefined) data.backendUrl = await checkUrl("backend_url", input.backend_url);
  if (input.email_webhook_url !== undefined) {
    data.emailWebhookUrl = input.email_webhook_url === null ? null : await checkUrl("email_webhook_url", input.email_webhook_url);
  }
  const updated = await getDb().application.update({ where: { id: app.id }, data });
  logger.info("app_updated", { appId: app.id, developer: dev.rapidApiUser, fields: Object.keys(data) });
  return { app: publicApp(updated) };
}

export async function deleteApp(dev: Developer, appId: string | string[] | undefined) {
  await enforceRateLimit(POLICIES.manage, dev.rapidApiUser);
  const app = await findOwned(dev, appId);
  // Cascades to sessions, refresh tokens and one-time tokens.
  await getDb().application.delete({ where: { id: app.id } });
  logger.info("app_deleted", { appId: app.id, developer: dev.rapidApiUser });
  return { deleted: true, app_id: app.id };
}

export async function rotateAppSecret(dev: Developer, appId: string | string[] | undefined) {
  await enforceRateLimit(POLICIES.manage, dev.rapidApiUser);
  const app = await findOwned(dev, appId);
  const appSecret = generateAppSecret();
  await getDb().application.update({ where: { id: app.id }, data: { secretHash: hashAppSecret(appSecret) } });
  logger.info("app_secret_rotated", { appId: app.id, developer: dev.rapidApiUser });
  return { app_id: app.id, app_secret: appSecret };
}

export async function rotateIntegrationSecret(dev: Developer, appId: string | string[] | undefined) {
  await enforceRateLimit(POLICIES.manage, dev.rapidApiUser);
  const app = await findOwned(dev, appId);
  const updated = await getDb().application.update({
    where: { id: app.id },
    data: { integrationSecretVersion: { increment: 1 } },
  });
  logger.info("integration_secret_rotated", { appId: app.id, developer: dev.rapidApiUser });
  return {
    app_id: app.id,
    integration_signing_secret: integrationSigningSecret(updated),
    integration_secret_version: updated.integrationSecretVersion,
  };
}

export async function testBackend(dev: Developer, appId: string | string[] | undefined) {
  await enforceRateLimit(POLICIES.test, dev.rapidApiUser);
  const app = await findOwned(dev, appId);
  const backend = await pingEndpoint(app, app.backendUrl);
  const emailWebhook = app.emailWebhookUrl ? await pingEndpoint(app, app.emailWebhookUrl) : null;
  return { ok: backend.ok && (emailWebhook?.ok ?? true), backend, email_webhook: emailWebhook };
}
