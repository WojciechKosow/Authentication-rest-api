import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { DELETE as deleteApp, GET as getApp, PATCH as patchApp } from "@/app/api/v1/apps/[appId]/route";
import { POST as rotateIntegration } from "@/app/api/v1/apps/[appId]/rotate-integration-secret/route";
import { POST as rotateSecret } from "@/app/api/v1/apps/[appId]/rotate-secret/route";
import { POST as testBackend } from "@/app/api/v1/apps/[appId]/test-backend/route";
import { GET as listApps, POST as createApp } from "@/app/api/v1/apps/route";
import { POST as login } from "@/app/api/v1/auth/login/route";
import { POST as register } from "@/app/api/v1/auth/register/route";
import { integrationSigningSecret } from "@/lib/apps";
import { resetConfigForTests } from "@/lib/config";
import { getDb } from "@/lib/db";
import { call, setupTestContext } from "./helpers";

const backend = setupTestContext();
const PROXY = "rapid-proxy-secret-for-tests-123456";
const CREDS = { email: "dave@example.com", password: "a-very-good-password" };

function as(user: string | null, extra: Record<string, string> = {}) {
  const h: Record<string, string> = { "x-rapidapi-proxy-secret": PROXY, ...extra };
  if (user) h["x-rapidapi-user"] = user;
  return h;
}

/** Call a dynamic [appId] route the way Next.js does (params as a Promise). */
function withParams(
  handler: (req: Request, ctx: { params: Promise<Record<string, string>> }) => Promise<Response>,
  appId: string,
) {
  return (req: Request) => handler(req, { params: Promise.resolve({ appId }) });
}

async function create(user = "alice_dev", body: Record<string, unknown> = {}) {
  return call(createApp, {
    headers: as(user),
    body: { name: "My App", backend_url: `${backend.url}/auth-hook`, ...body },
  });
}

beforeEach(() => {
  process.env.RAPIDAPI_PROXY_SECRET = PROXY;
  delete process.env.MAX_APPS_PER_DEVELOPER;
  process.env.INTEGRATION_ALLOW_PRIVATE_URLS = "true";
  resetConfigForTests();
});

afterAll(() => {
  delete process.env.RAPIDAPI_PROXY_SECRET;
  delete process.env.MAX_APPS_PER_DEVELOPER;
  process.env.INTEGRATION_ALLOW_PRIVATE_URLS = "true";
  resetConfigForTests();
});

describe("self-service application creation", () => {
  it("creates an app bound to the RapidAPI user and returns working credentials once", async () => {
    const res = await create();
    expect(res.status).toBe(201);
    const { app, credentials } = res.json.data;
    expect(app.app_id).toMatch(/^app_[a-f0-9]{24}$/);
    expect(app).not.toHaveProperty("rapid_api_user");
    expect(credentials.app_secret).toMatch(/^sk_/);
    expect(credentials.integration_signing_secret).toMatch(/^whsec_/);

    const row = await getDb().application.findUniqueOrThrow({ where: { id: app.app_id } });
    expect(row.rapidApiUser).toBe("alice_dev");
    expect(row.secretHash).not.toContain(credentials.app_secret);

    const appCreds = { id: app.app_id, secret: credentials.app_secret };
    const owner = await call(register, { app: appCreds, body: CREDS, headers: as("alice_dev") });
    expect(owner.status).toBe(201);

    // A different RapidAPI subscriber cannot use leaked credentials.
    const thief = await call(login, { app: appCreds, body: CREDS, headers: as("mallory") });
    expect(thief.status).toBe(403);
    expect(thief.json.error.code).toBe("APP_ACCESS_DENIED");

    // Secrets are never returned again.
    const fetched = await call(withParams(getApp, app.app_id), { headers: as("alice_dev") });
    expect(JSON.stringify(fetched.json)).not.toContain(credentials.app_secret);
    expect(JSON.stringify(fetched.json)).not.toContain("whsec_");
  });

  it("requires the RapidAPI gateway and a developer identity", async () => {
    const noProxy = await call(createApp, {
      headers: { "x-rapidapi-user": "alice_dev" },
      body: { name: "x", backend_url: `${backend.url}/auth-hook` },
    });
    expect(noProxy.status).toBe(403);
    expect(noProxy.json.error.code).toBe("PROXY_AUTH_FAILED");

    const noUser = await call(createApp, { headers: as(null), body: { name: "x", backend_url: `${backend.url}/a` } });
    expect(noUser.status).toBe(401);
    expect(noUser.json.error.code).toBe("MISSING_DEVELOPER_IDENTITY");

    // Without a configured gateway secret the identity header could be forged: refuse.
    delete process.env.RAPIDAPI_PROXY_SECRET;
    resetConfigForTests();
    const unconfigured = await call(createApp, {
      headers: { "x-rapidapi-user": "alice_dev" },
      body: { name: "x", backend_url: `${backend.url}/a` },
    });
    expect(unconfigured.status).toBe(403);
    expect(unconfigured.json.error.code).toBe("PROXY_AUTH_FAILED");
    expect(await getDb().application.count()).toBe(0);
  });

  it("enforces the per-developer application limit", async () => {
    process.env.MAX_APPS_PER_DEVELOPER = "2";
    resetConfigForTests();
    expect((await create()).status).toBe(201);
    expect((await create()).status).toBe(201);
    const third = await create();
    expect(third.status).toBe(403);
    expect(third.json.error.code).toBe("APP_LIMIT_REACHED");
    // Limits are per developer.
    expect((await create("bob_dev")).status).toBe(201);
  });

  it("enforces the limit under concurrent creation", async () => {
    process.env.MAX_APPS_PER_DEVELOPER = "2";
    resetConfigForTests();
    const results = await Promise.all([0, 1, 2, 3, 4].map(() => create()));
    expect(results.filter((r) => r.status === 201)).toHaveLength(2);
    expect(await getDb().application.count({ where: { rapidApiUser: "alice_dev" } })).toBe(2);
  });

  it.each([
    ["http://api.example.com/hook", "https"],
    ["https://127.0.0.1/hook", "private"],
    ["https://169.254.169.254/latest/meta-data", "private"],
    ["https://[::ffff:10.0.0.1]/hook", "private"],
    ["https://localhost/hook", "public domain"],
    ["https://db.railway.internal/hook", "public domain"],
    ["https://auth.test.local/api/v1/auth/login", "public domain"],
    ["https://auth-api.p.rapidapi.com/hook", "this API"],
    ["https://user:pw@api.example.com/hook", "credentials"],
  ])("rejects unsafe integration URL %s", async (url, reason) => {
    process.env.INTEGRATION_ALLOW_PRIVATE_URLS = "false";
    resetConfigForTests();
    const res = await create("alice_dev", { backend_url: url });
    expect(res.status).toBe(400);
    expect(res.json.error.code).toBe("INVALID_INTEGRATION_URL");
    expect(res.json.error.details[0].path).toBe("backend_url");
    expect(res.json.error.details[0].message).toContain(reason);
  });

  it("refuses integration URLs pointing back at this API", async () => {
    process.env.JWT_ISSUER = "https://auth.xyz.com";
    process.env.INTEGRATION_ALLOW_PRIVATE_URLS = "false";
    resetConfigForTests();
    try {
      for (const url of ["https://auth.xyz.com/api/v1/auth/register", "https://api.auth.xyz.com/hook"]) {
        const res = await create("alice_dev", { backend_url: url });
        expect(res.status).toBe(400);
        expect(res.json.error.details[0].message).toContain("this API");
      }
    } finally {
      process.env.JWT_ISSUER = "https://auth.test.local";
      resetConfigForTests();
    }
  });

  it("validates the request body", async () => {
    const missing = await call(createApp, { headers: as("alice_dev"), body: { name: "x" } });
    expect(missing.status).toBe(400);
    expect(missing.json.error.code).toBe("VALIDATION_ERROR");
    const extra = await create("alice_dev", { rapidapi_user: "someone_else" });
    expect(extra.status).toBe(400);
  });
});

describe("self-service application management", () => {
  it("lists only the caller's applications and hides foreign ones (404)", async () => {
    const mine = (await create("alice_dev")).json.data.app;
    const theirs = (await create("bob_dev")).json.data.app;

    const list = await call(listApps, { headers: as("alice_dev") });
    expect(list.status).toBe(200);
    expect(list.json.data.apps.map((a: { app_id: string }) => a.app_id)).toEqual([mine.app_id]);
    expect(list.json.data.limit).toBe(5);

    for (const [handler, body] of [
      [getApp, undefined],
      [patchApp, { name: "pwned" }],
      [deleteApp, undefined],
    ] as const) {
      const res = await call(withParams(handler, theirs.app_id), {
        headers: as("alice_dev"),
        body,
        method: handler === getApp ? "GET" : handler === patchApp ? "PATCH" : "DELETE",
      });
      expect(res.status).toBe(404);
    }
    for (const handler of [rotateSecret, rotateIntegration, testBackend]) {
      const res = await call(withParams(handler, theirs.app_id), { headers: as("alice_dev"), method: "POST" });
      expect(res.status).toBe(404);
    }
    const untouched = await getDb().application.findUniqueOrThrow({ where: { id: theirs.app_id } });
    expect(untouched.name).toBe("My App");

    const malformed = await call(withParams(getApp, "../../etc"), { headers: as("alice_dev") });
    expect(malformed.status).toBe(404);
  });

  it("updates an application", async () => {
    const app = (await create("alice_dev", { email_webhook_url: `${backend.url}/email-hook` })).json.data.app;
    expect(app.email_webhook_url).toBe(`${backend.url}/email-hook`);
    const res = await call(withParams(patchApp, app.app_id), {
      headers: as("alice_dev"),
      method: "PATCH",
      body: { name: "Renamed", backend_url: `${backend.url}/v2/auth-hook`, email_webhook_url: null },
    });
    expect(res.status).toBe(200);
    expect(res.json.data.app).toMatchObject({
      name: "Renamed",
      backend_url: `${backend.url}/v2/auth-hook`,
      email_webhook_url: null,
    });

    const empty = await call(withParams(patchApp, app.app_id), { headers: as("alice_dev"), method: "PATCH", body: {} });
    expect(empty.status).toBe(400);
  });

  it("rotates the app secret: the old one stops working immediately", async () => {
    const { app, credentials } = (await create()).json.data;
    const res = await call(withParams(rotateSecret, app.app_id), { headers: as("alice_dev"), method: "POST" });
    expect(res.status).toBe(200);
    const fresh = res.json.data.app_secret;
    expect(fresh).not.toBe(credentials.app_secret);

    const old = await call(register, { app: { id: app.app_id, secret: credentials.app_secret }, body: CREDS, headers: as("alice_dev") });
    expect(old.json.error.code).toBe("INVALID_APP_CREDENTIALS");
    const ok = await call(register, { app: { id: app.app_id, secret: fresh }, body: CREDS, headers: as("alice_dev") });
    expect(ok.status).toBe(201);
  });

  it("rotates the integration signing secret", async () => {
    const { app, credentials } = (await create()).json.data;
    const res = await call(withParams(rotateIntegration, app.app_id), { headers: as("alice_dev"), method: "POST" });
    expect(res.status).toBe(200);
    expect(res.json.data.integration_signing_secret).not.toBe(credentials.integration_signing_secret);
    expect(res.json.data.integration_signing_secret).toBe(
      integrationSigningSecret({ id: app.app_id, integrationSecretVersion: 2 }),
    );
    // The mock backend still verifies with the old (v1) secret, so the connection test reports it.
    const test = await call(withParams(testBackend, app.app_id), { headers: as("alice_dev"), method: "POST" });
    expect(test.json.data.ok).toBe(false);
    expect(test.json.data.backend.status).toBe(401);
    expect(test.json.data.backend.error).toMatch(/signature/);
  });

  it("tests connectivity to the developer backend", async () => {
    const { app } = (await create("alice_dev", { email_webhook_url: `${backend.url}/email-hook` })).json.data;
    const ok = await call(withParams(testBackend, app.app_id), { headers: as("alice_dev"), method: "POST" });
    expect(ok.status).toBe(200);
    expect(ok.json.data).toMatchObject({
      ok: true,
      backend: { ok: true, status: 200, error: null },
      email_webhook: { ok: true, status: 200, error: null },
    });

    backend.mode = "timeout";
    const slow = await call(withParams(testBackend, app.app_id), { headers: as("alice_dev"), method: "POST" });
    expect(slow.json.data.ok).toBe(false);
    expect(slow.json.data.backend.error).toMatch(/in time/);

    backend.mode = "error500";
    const broken = await call(withParams(testBackend, app.app_id), { headers: as("alice_dev"), method: "POST" });
    expect(broken.json.data.backend).toMatchObject({ ok: false, status: 500 });
  });

  it("deletes an application and everything that belongs to it", async () => {
    const { app, credentials } = (await create()).json.data;
    const appCreds = { id: app.app_id, secret: credentials.app_secret };
    expect((await call(register, { app: appCreds, body: CREDS, headers: as("alice_dev") })).status).toBe(201);
    expect(await getDb().session.count()).toBe(1);

    const res = await call(withParams(deleteApp, app.app_id), { headers: as("alice_dev"), method: "DELETE" });
    expect(res.status).toBe(200);
    expect(res.json.data).toEqual({ deleted: true, app_id: app.app_id });
    expect(await getDb().session.count()).toBe(0);
    const after = await call(login, { app: appCreds, body: CREDS, headers: as("alice_dev") });
    expect(after.json.error.code).toBe("INVALID_APP_CREDENTIALS");
  });
});
