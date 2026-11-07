import { describe, expect, it } from "vitest";
import { GET as notFound } from "@/app/[...path]/route";
import { GET as health } from "@/app/api/v1/health/route";
import { POST as login } from "@/app/api/v1/auth/login/route";
import { GET as me } from "@/app/api/v1/auth/me/route";
import { POST as refresh } from "@/app/api/v1/auth/refresh/route";
import { POST as register } from "@/app/api/v1/auth/register/route";
import { POST as validate } from "@/app/api/v1/auth/validate/route";
import { resetConfigForTests } from "@/lib/config";
import { call, createTestApp, setupTestContext } from "./helpers";

const backend = setupTestContext();
const CREDS = { email: "bob@example.com", password: "a-very-good-password" };

describe("application isolation", () => {
  it("never accepts tokens of one application in another", async () => {
    const appA = await createTestApp(backend.url);
    const appB = await createTestApp(backend.url);
    const { tokens } = (await call(register, { app: appA, body: CREDS })).json.data;

    const v = await call(validate, { app: appB, body: { access_token: tokens.access_token } });
    expect(v.status).toBe(401);
    expect(v.json.error.code).toBe("INVALID_TOKEN");

    const m = await call(me, { app: appB, bearer: tokens.access_token });
    expect(m.json.error.code).toBe("INVALID_TOKEN");

    const r = await call(refresh, { app: appB, body: { refresh_token: tokens.refresh_token } });
    expect(r.status).toBe(401);
    expect(r.json.error.code).toBe("INVALID_REFRESH_TOKEN");

    // The foreign attempt must not have harmed the legitimate session.
    const ok = await call(refresh, { app: appA, body: { refresh_token: tokens.refresh_token } });
    expect(ok.status).toBe(200);
  });

  it("keeps user namespaces separate per application", async () => {
    const appA = await createTestApp(backend.url);
    const appB = await createTestApp(backend.url);
    await call(register, { app: appA, body: CREDS });
    const res = await call(login, { app: appB, body: CREDS });
    expect(res.status).toBe(401);
    expect(res.json.error.code).toBe("INVALID_CREDENTIALS");
    // Registering the same email in app B is allowed (separate namespace).
    expect((await call(register, { app: appB, body: CREDS })).status).toBe(201);
  });

  it("rejects missing, wrong, and cross-app credentials", async () => {
    const appA = await createTestApp(backend.url);
    const appB = await createTestApp(backend.url);
    const missing = await call(login, { body: CREDS });
    expect(missing.status).toBe(401);
    expect(missing.json.error.code).toBe("MISSING_APP_CREDENTIALS");

    const wrong = await call(login, { app: { id: appA.id, secret: appB.secret }, body: CREDS });
    expect(wrong.status).toBe(401);
    expect(wrong.json.error.code).toBe("INVALID_APP_CREDENTIALS");

    const unknown = await call(login, { app: { id: "app_000000000000000000000000", secret: appA.secret }, body: CREDS });
    expect(unknown.json.error.code).toBe("INVALID_APP_CREDENTIALS");
  });

  it("rejects disabled applications", async () => {
    const app = await createTestApp(backend.url, { isActive: false });
    const res = await call(login, { app, body: CREDS });
    expect(res.json.error.code).toBe("INVALID_APP_CREDENTIALS");
  });

  it("enforces the optional RapidAPI user binding", async () => {
    const app = await createTestApp(backend.url, { rapidApiUser: "acme_dev" });
    const other = await call(register, { app, body: CREDS, headers: { "x-rapidapi-user": "mallory" } });
    expect(other.status).toBe(403);
    expect(other.json.error.code).toBe("APP_ACCESS_DENIED");
    const owner = await call(register, { app, body: CREDS, headers: { "x-rapidapi-user": "acme_dev" } });
    expect(owner.status).toBe(201);
  });
});

describe("request validation", () => {
  it.each([
    [{ password: "a-very-good-password" }, "email"],
    [{ email: "not-an-email", password: "a-very-good-password" }, "email"],
    [{ email: "bob@example.com", password: "short" }, "password"],
    [{ email: "bob@example.com", password: "x".repeat(129) }, "password"],
    [{ email: "bob@example.com", password: 12345678 }, "password"],
    [{ ...{ email: "bob@example.com", password: "a-very-good-password" }, user_id: "admin" }, ""],
  ])("rejects invalid register body %j", async (body, field) => {
    const app = await createTestApp(backend.url);
    const res = await call(register, { app, body });
    expect(res.status).toBe(400);
    expect(res.json.error.code).toBe("VALIDATION_ERROR");
    expect(res.json.error.details.length).toBeGreaterThan(0);
    if (field) expect(res.json.error.details[0].path).toBe(field);
    expect(backend.rawBodies).toHaveLength(0); // backend never called
  });

  it("rejects malformed JSON, wrong content type, and oversized bodies", async () => {
    const app = await createTestApp(backend.url);
    const badJson = await call(login, { app, rawBody: "{not json" });
    expect(badJson.status).toBe(400);
    expect(badJson.json.error.code).toBe("INVALID_JSON");

    const form = await call(login, { app, rawBody: "email=a", headers: { "content-type": "application/x-www-form-urlencoded" } });
    expect(form.status).toBe(415);
    expect(form.json.error.code).toBe("UNSUPPORTED_MEDIA_TYPE");

    const big = await call(login, { app, rawBody: JSON.stringify({ email: "a@b.co", password: "x".repeat(20_000) }) });
    expect(big.status).toBe(413);
    expect(big.json.error.code).toBe("PAYLOAD_TOO_LARGE");
  });

  it("rejects malformed refresh tokens before touching the database", async () => {
    const app = await createTestApp(backend.url);
    const res = await call(refresh, { app, body: { refresh_token: "' OR 1=1 --" } });
    expect(res.status).toBe(400);
    expect(res.json.error.code).toBe("VALIDATION_ERROR");
  });
});

describe("gateway, headers and misc", () => {
  it("requires the RapidAPI proxy secret when configured", async () => {
    process.env.RAPIDAPI_PROXY_SECRET = "rapid-proxy-secret-for-tests-123456";
    resetConfigForTests();
    try {
      const app = await createTestApp(backend.url);
      const without = await call(register, { app, body: CREDS });
      expect(without.status).toBe(403);
      expect(without.json.error.code).toBe("PROXY_AUTH_FAILED");
      const wrong = await call(register, { app, body: CREDS, headers: { "x-rapidapi-proxy-secret": "nope" } });
      expect(wrong.status).toBe(403);
      const ok = await call(register, {
        app,
        body: CREDS,
        headers: { "x-rapidapi-proxy-secret": "rapid-proxy-secret-for-tests-123456" },
      });
      expect(ok.status).toBe(201);
      // Health check stays reachable for the platform (Railway).
      expect((await call(health)).status).toBe(200);
    } finally {
      delete process.env.RAPIDAPI_PROXY_SECRET;
      resetConfigForTests();
    }
  });

  it("sets security headers, request id and no CORS for unknown origins", async () => {
    const app = await createTestApp(backend.url);
    const res = await call(register, { app, body: CREDS, headers: { origin: "https://evil.example" } });
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/);
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("reports health and returns JSON 404s", async () => {
    const h = await call(health);
    expect(h.status).toBe(200);
    expect(h.json.data).toMatchObject({ status: "ok", checks: { database: "ok", rate_limiter: "ok", rate_limiter_store: "memory" } });
    const nf = await call(notFound, { path: "/api/v1/nope" });
    expect(nf.status).toBe(404);
    expect(nf.json).toEqual({ success: false, data: null, error: { code: "NOT_FOUND", message: expect.any(String) } });
  });
});
