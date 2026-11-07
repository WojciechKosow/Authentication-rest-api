/**
 * Application provisioning CLI (operator-only; there is intentionally no public endpoint).
 *
 *   npm run apps -- create --name "Acme" --backend-url https://api.acme.com/auth-hook \
 *        [--email-webhook-url https://api.acme.com/auth-email] [--rapidapi-user acme_dev]
 *   npm run apps -- list
 *   npm run apps -- show --app-id app_...
 *   npm run apps -- update --app-id app_... [--name ..] [--backend-url ..] [--email-webhook-url ..|--clear-email-webhook]
 *        [--rapidapi-user ..|--clear-rapidapi-user]
 *   npm run apps -- rotate-secret --app-id app_...               (new X-App-Secret)
 *   npm run apps -- rotate-integration-secret --app-id app_...   (new backend signing secret)
 *   npm run apps -- rotate-jwt-key --app-id app_...              (invalidates all access tokens)
 *   npm run apps -- disable|enable --app-id app_...
 *   npm run apps -- cleanup [--days 7]                           (purge expired/revoked records)
 *
 * Requires the same environment variables as the server (DATABASE_URL, JWT_MASTER_SECRET,
 * INTEGRATION_MASTER_SECRET, ...).
 */
import { lookup } from "node:dns/promises";
import { parseArgs } from "node:util";
import { APP_ID_PATTERN, generateAppId, generateAppSecret, hashAppSecret, integrationSigningSecret } from "@/lib/apps";
import { getConfig } from "@/lib/config";
import { disconnectDb, getDb } from "@/lib/db";
import { assertSafeUrl, isPublicIp } from "@/lib/ssrf";

const { positionals, values } = parseArgs({
  allowPositionals: true,
  options: {
    name: { type: "string" },
    "app-id": { type: "string" },
    "backend-url": { type: "string" },
    "email-webhook-url": { type: "string" },
    "clear-email-webhook": { type: "boolean" },
    "rapidapi-user": { type: "string" },
    "clear-rapidapi-user": { type: "boolean" },
    days: { type: "string" },
  },
});

function fail(message: string): never {
  console.error(`Error: ${message}`);
  process.exit(1);
}

async function validateUrl(label: string, raw: string): Promise<string> {
  const { integrationAllowPrivateUrls } = getConfig();
  let url: URL;
  try {
    url = assertSafeUrl(raw, integrationAllowPrivateUrls);
  } catch (err) {
    fail(`${label}: ${(err as Error).message}`);
  }
  if (!integrationAllowPrivateUrls) {
    const host = url.hostname.replace(/^\[|\]$/g, "");
    const addresses = await lookup(host, { all: true }).catch(() => fail(`${label}: host ${host} does not resolve`));
    if (addresses.some((a) => !isPublicIp(a.address))) fail(`${label}: host resolves to a private/reserved address`);
  }
  return url.toString();
}

function requireAppId(): string {
  const id = values["app-id"];
  if (!id || !APP_ID_PATTERN.test(id)) fail("--app-id app_<24 hex> is required");
  return id;
}

function publicView(app: Awaited<ReturnType<ReturnType<typeof getDb>["application"]["findUniqueOrThrow"]>>) {
  return {
    app_id: app.id,
    name: app.name,
    backend_url: app.backendUrl,
    email_webhook_url: app.emailWebhookUrl,
    rapidapi_user: app.rapidApiUser,
    is_active: app.isActive,
    jwt_key_version: app.jwtKeyVersion,
    integration_secret_version: app.integrationSecretVersion,
    created_at: app.createdAt.toISOString(),
  };
}

async function main() {
  const db = getDb();
  const command = positionals[0];

  switch (command) {
    case "create": {
      if (!values.name) fail("--name is required");
      if (!values["backend-url"]) fail("--backend-url is required");
      const backendUrl = await validateUrl("--backend-url", values["backend-url"]);
      const emailWebhookUrl = values["email-webhook-url"]
        ? await validateUrl("--email-webhook-url", values["email-webhook-url"])
        : null;
      const appSecret = generateAppSecret();
      const app = await db.application.create({
        data: {
          id: generateAppId(),
          name: values.name,
          secretHash: hashAppSecret(appSecret),
          backendUrl,
          emailWebhookUrl,
          rapidApiUser: values["rapidapi-user"] ?? null,
        },
      });
      console.log(JSON.stringify({ ...publicView(app), app_secret: appSecret, integration_signing_secret: integrationSigningSecret(app) }, null, 2));
      console.error("\nStore app_secret and integration_signing_secret now. They are NOT shown again (rotate to get new ones).");
      break;
    }
    case "list": {
      const apps = await db.application.findMany({ orderBy: { createdAt: "asc" } });
      console.log(JSON.stringify(apps.map(publicView), null, 2));
      break;
    }
    case "show": {
      const app = await db.application.findUnique({ where: { id: requireAppId() } });
      if (!app) fail("application not found");
      console.log(JSON.stringify(publicView(app), null, 2));
      break;
    }
    case "update": {
      const id = requireAppId();
      const data: Record<string, unknown> = {};
      if (values.name) data.name = values.name;
      if (values["backend-url"]) data.backendUrl = await validateUrl("--backend-url", values["backend-url"]);
      if (values["email-webhook-url"]) data.emailWebhookUrl = await validateUrl("--email-webhook-url", values["email-webhook-url"]);
      if (values["clear-email-webhook"]) data.emailWebhookUrl = null;
      if (values["rapidapi-user"]) data.rapidApiUser = values["rapidapi-user"];
      if (values["clear-rapidapi-user"]) data.rapidApiUser = null;
      if (!Object.keys(data).length) fail("nothing to update");
      const app = await db.application.update({ where: { id }, data });
      console.log(JSON.stringify(publicView(app), null, 2));
      break;
    }
    case "rotate-secret": {
      const appSecret = generateAppSecret();
      const app = await db.application.update({ where: { id: requireAppId() }, data: { secretHash: hashAppSecret(appSecret) } });
      console.log(JSON.stringify({ app_id: app.id, app_secret: appSecret }, null, 2));
      break;
    }
    case "rotate-integration-secret": {
      const app = await db.application.update({
        where: { id: requireAppId() },
        data: { integrationSecretVersion: { increment: 1 } },
      });
      console.log(JSON.stringify({ app_id: app.id, integration_signing_secret: integrationSigningSecret(app) }, null, 2));
      break;
    }
    case "rotate-jwt-key": {
      const app = await db.application.update({ where: { id: requireAppId() }, data: { jwtKeyVersion: { increment: 1 } } });
      console.log(JSON.stringify({ app_id: app.id, jwt_key_version: app.jwtKeyVersion }, null, 2));
      break;
    }
    case "disable":
    case "enable": {
      const app = await db.application.update({ where: { id: requireAppId() }, data: { isActive: command === "enable" } });
      console.log(JSON.stringify(publicView(app), null, 2));
      break;
    }
    case "cleanup": {
      const days = Number(values.days ?? "7");
      if (!Number.isFinite(days) || days < 0) fail("--days must be a non-negative number");
      const cutoff = new Date(Date.now() - days * 86_400_000);
      const sessions = await db.session.deleteMany({
        where: { OR: [{ expiresAt: { lt: cutoff } }, { revokedAt: { lt: cutoff } }] },
      });
      const oneTime = await db.oneTimeToken.deleteMany({
        where: { OR: [{ expiresAt: { lt: cutoff } }, { usedAt: { lt: cutoff } }] },
      });
      console.log(JSON.stringify({ deleted_sessions: sessions.count, deleted_one_time_tokens: oneTime.count }));
      break;
    }
    default:
      fail(`unknown command '${command ?? ""}'. See scripts/apps.ts for usage.`);
  }
}

main()
  .catch((err) => fail(err instanceof Error ? err.message : String(err)))
  .finally(() => disconnectDb());
