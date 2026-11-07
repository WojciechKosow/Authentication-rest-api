import { describe, expect, it } from "vitest";
import { POST as confirmVerify } from "@/app/api/v1/auth/email/verify/confirm/route";
import { POST as requestVerify } from "@/app/api/v1/auth/email/verify/request/route";
import { POST as login } from "@/app/api/v1/auth/login/route";
import { GET as me } from "@/app/api/v1/auth/me/route";
import { POST as confirmReset } from "@/app/api/v1/auth/password/reset/confirm/route";
import { POST as requestReset } from "@/app/api/v1/auth/password/reset/request/route";
import { POST as register } from "@/app/api/v1/auth/register/route";
import { POST as validate } from "@/app/api/v1/auth/validate/route";
import { getDb } from "@/lib/db";
import { call, createTestApp, setupTestContext } from "./helpers";

const backend = setupTestContext();
const CREDS = { email: "carol@example.com", password: "a-very-good-password" };

describe("developer backend failures", () => {
  it("maps a 5xx backend response to 502 INTEGRATION_ERROR", async () => {
    const app = await createTestApp(backend.url);
    backend.mode = "error500";
    const res = await call(register, { app, body: CREDS });
    expect(res.status).toBe(502);
    expect(res.json.error.code).toBe("INTEGRATION_ERROR");
    expect(await getDb().session.count()).toBe(0);
  });

  it("maps a slow backend to 504 INTEGRATION_TIMEOUT", async () => {
    const app = await createTestApp(backend.url);
    backend.mode = "timeout";
    const started = Date.now();
    const res = await call(login, { app, body: CREDS });
    expect(res.status).toBe(504);
    expect(res.json.error.code).toBe("INTEGRATION_TIMEOUT");
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it("rejects responses that violate the contract", async () => {
    const app = await createTestApp(backend.url);
    backend.mode = "invalid-shape";
    const reg = await call(register, { app, body: CREDS });
    expect(reg.status).toBe(502);
    expect(reg.json.error.code).toBe("INTEGRATION_ERROR");

    backend.mode = "html";
    expect((await call(login, { app, body: CREDS })).json.error.code).toBe("INTEGRATION_ERROR");
  });

  it("refuses non-Argon2id password hashes from the backend", async () => {
    const app = await createTestApp(backend.url);
    await call(register, { app, body: CREDS });
    backend.mode = "bad-hash";
    const res = await call(login, { app, body: CREDS });
    expect(res.status).toBe(502);
    expect(res.json.error.code).toBe("INTEGRATION_ERROR");
  });

  it("does not follow redirects", async () => {
    const app = await createTestApp(backend.url);
    backend.mode = "redirect";
    const res = await call(login, { app, body: CREDS });
    expect(res.status).toBe(502);
    expect(backend.rawBodies).toHaveLength(1);
  });

  it("signs every request so the backend can authenticate it", async () => {
    const app = await createTestApp(backend.url);
    expect((await call(register, { app, body: CREDS })).status).toBe(201);
    expect((await call(login, { app, body: CREDS })).status).toBe(200);
    expect(backend.signatureFailures).toBe(0);
  });

  it("revokes sessions when the backend reports the user as deleted", async () => {
    const app = await createTestApp(backend.url);
    const { tokens } = (await call(register, { app, body: CREDS })).json.data;
    backend.usersOf(app.id).clear();
    const res = await call(me, { app, bearer: tokens.access_token });
    expect(res.status).toBe(401);
    expect(res.json.error.code).toBe("SESSION_REVOKED");
    expect((await call(validate, { app, body: { access_token: tokens.access_token } })).status).toBe(401);
  });
});

describe("email verification (optional webhook)", () => {
  it("returns 501 when the email webhook is not configured; core auth still works", async () => {
    const app = await createTestApp(backend.url);
    expect((await call(register, { app, body: CREDS })).status).toBe(201);
    const res = await call(requestVerify, { app, body: { email: CREDS.email } });
    expect(res.status).toBe(501);
    expect(res.json.error.code).toBe("FEATURE_NOT_CONFIGURED");
  });

  it("runs the full verification flow with single-use tokens", async () => {
    const app = await createTestApp(backend.url, { emailWebhook: true });
    await call(register, { app, body: CREDS });

    const req = await call(requestVerify, { app, body: { email: CREDS.email } });
    expect(req.status).toBe(202);
    expect(req.json.data).toEqual({ accepted: true }); // token never in the API response
    expect(backend.emails).toHaveLength(1);
    const mail = backend.emails[0];
    expect(mail).toMatchObject({ type: "email_verification", to: CREDS.email, user_id: "usr_1" });
    expect(mail.token).toMatch(/^ev_/);

    const ok = await call(confirmVerify, { app, body: { token: mail.token } });
    expect(ok.status).toBe(200);
    expect(ok.json.data).toEqual({ user_id: "usr_1", email: CREDS.email, email_verified: true });
    expect(backend.usersOf(app.id).get(CREDS.email)!.email_verified).toBe(true);

    const again = await call(confirmVerify, { app, body: { token: mail.token } });
    expect(again.status).toBe(400);
    expect(again.json.error.code).toBe("INVALID_ONE_TIME_TOKEN");

    // Tokens are stored hashed.
    const row = await getDb().oneTimeToken.findFirstOrThrow();
    expect(row.tokenHash).not.toContain(mail.token);
  });

  it("does not reveal whether an email exists", async () => {
    const app = await createTestApp(backend.url, { emailWebhook: true });
    const res = await call(requestVerify, { app, body: { email: "ghost@example.com" } });
    expect(res.status).toBe(202);
    expect(res.json.data).toEqual({ accepted: true });
    expect(backend.emails).toHaveLength(0);
  });

  it("rejects expired tokens and tokens from another application", async () => {
    const appA = await createTestApp(backend.url, { emailWebhook: true });
    const appB = await createTestApp(backend.url, { emailWebhook: true });
    await call(register, { app: appA, body: CREDS });
    await call(requestVerify, { app: appA, body: { email: CREDS.email } });
    const token = backend.emails[0].token;

    const cross = await call(confirmVerify, { app: appB, body: { token } });
    expect(cross.json.error.code).toBe("INVALID_ONE_TIME_TOKEN");

    await getDb().oneTimeToken.updateMany({ data: { expiresAt: new Date(Date.now() - 1000) } });
    const expired = await call(confirmVerify, { app: appA, body: { token } });
    expect(expired.json.error.code).toBe("INVALID_ONE_TIME_TOKEN");
  });
});

describe("password reset (optional webhook)", () => {
  it("resets the password, revokes sessions and invalidates the token", async () => {
    const app = await createTestApp(backend.url, { emailWebhook: true });
    const { tokens } = (await call(register, { app, body: CREDS })).json.data;

    expect((await call(requestReset, { app, body: { email: CREDS.email } })).status).toBe(202);
    const mail = backend.emails.find((e) => e.type === "password_reset")!;
    expect(mail.token).toMatch(/^pr_/);

    const NEW = "a-brand-new-password";
    const res = await call(confirmReset, { app, body: { token: mail.token, new_password: NEW } });
    expect(res.status).toBe(200);
    expect(res.json.data).toEqual({ password_reset: true, sessions_revoked: 1 });

    expect((await call(validate, { app, body: { access_token: tokens.access_token } })).status).toBe(401);
    expect((await call(login, { app, body: CREDS })).status).toBe(401);
    expect((await call(login, { app, body: { email: CREDS.email, password: NEW } })).status).toBe(200);
    for (const raw of backend.rawBodies) expect(raw).not.toContain(NEW);

    const reuse = await call(confirmReset, { app, body: { token: mail.token, new_password: "another-password-1" } });
    expect(reuse.json.error.code).toBe("INVALID_ONE_TIME_TOKEN");
  });

  it("only the latest reset token is valid", async () => {
    const app = await createTestApp(backend.url, { emailWebhook: true });
    await call(register, { app, body: CREDS });
    await call(requestReset, { app, body: { email: CREDS.email } });
    await call(requestReset, { app, body: { email: CREDS.email } });
    const [first, second] = backend.emails;
    expect((await call(confirmReset, { app, body: { token: first.token, new_password: "new-password-123" } })).status).toBe(400);
    expect((await call(confirmReset, { app, body: { token: second.token, new_password: "new-password-123" } })).status).toBe(200);
  });

  it("keeps the token usable if the backend fails during confirmation", async () => {
    const app = await createTestApp(backend.url, { emailWebhook: true });
    await call(register, { app, body: CREDS });
    await call(requestReset, { app, body: { email: CREDS.email } });
    const token = backend.emails[0].token;
    backend.mode = "error500";
    expect((await call(confirmReset, { app, body: { token, new_password: "new-password-123" } })).status).toBe(502);
    backend.mode = "ok";
    expect((await call(confirmReset, { app, body: { token, new_password: "new-password-123" } })).status).toBe(200);
  });
});
