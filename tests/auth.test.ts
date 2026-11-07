import { describe, expect, it } from "vitest";
import { POST as login } from "@/app/api/v1/auth/login/route";
import { POST as logout } from "@/app/api/v1/auth/logout/route";
import { GET as me } from "@/app/api/v1/auth/me/route";
import { POST as refresh } from "@/app/api/v1/auth/refresh/route";
import { POST as register } from "@/app/api/v1/auth/register/route";
import { POST as validate } from "@/app/api/v1/auth/validate/route";
import { getDb } from "@/lib/db";
import { signAccessToken } from "@/lib/jwt";
import { call, createTestApp, TestApp, setupTestContext } from "./helpers";

const backend = setupTestContext();
const EMAIL = "Alice@Example.com";
const PASSWORD = "correct horse battery staple";

async function registerUser(app: TestApp, email = EMAIL, password = PASSWORD) {
  const res = await call(register, { app, body: { email, password } });
  expect(res.status).toBe(201);
  return res.json.data as {
    user: { user_id: string; email: string };
    tokens: { access_token: string; refresh_token: string; session_id: string };
  };
}

describe("registration", () => {
  it("registers a user, sends only an Argon2id hash to the backend and returns tokens", async () => {
    const app = await createTestApp(backend.url);
    const res = await call(register, { app, body: { email: EMAIL, password: PASSWORD } });

    expect(res.status).toBe(201);
    expect(res.json).toMatchObject({ success: true, error: null });
    expect(res.json.data.user).toEqual({ user_id: "usr_1", email: "alice@example.com", email_verified: false });
    expect(res.json.data.tokens).toMatchObject({ token_type: "Bearer", expires_in: 900 });
    expect(res.json.data.tokens.refresh_token).toMatch(/^rt_/);

    const stored = backend.usersOf(app.id).get("alice@example.com")!;
    expect(stored.password_hash).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    for (const raw of backend.rawBodies) expect(raw).not.toContain(PASSWORD);

    // Refresh tokens are stored hashed only.
    const rows = await getDb().refreshToken.findMany();
    expect(rows).toHaveLength(1);
    expect(rows[0].tokenHash).toMatch(/^[a-f0-9]{64}$/);
    expect(rows[0].tokenHash).not.toBe(res.json.data.tokens.refresh_token);
  });

  it("rejects duplicate registration with 409", async () => {
    const app = await createTestApp(backend.url);
    await registerUser(app);
    const res = await call(register, { app, body: { email: "alice@example.com", password: PASSWORD } });
    expect(res.status).toBe(409);
    expect(res.json).toEqual({
      success: false,
      data: null,
      error: { code: "EMAIL_ALREADY_REGISTERED", message: expect.any(String) },
    });
  });
});

describe("login", () => {
  it("logs in with the correct password", async () => {
    const app = await createTestApp(backend.url);
    await registerUser(app);
    const res = await call(login, { app, body: { email: EMAIL, password: PASSWORD } });
    expect(res.status).toBe(200);
    expect(res.json.data.user).toMatchObject({ user_id: "usr_1", email: "alice@example.com" });
    expect(res.json.data.tokens.access_token.split(".")).toHaveLength(3);
    for (const raw of backend.rawBodies) expect(raw).not.toContain(PASSWORD);
  });

  it("returns the same generic error for a wrong password and an unknown email", async () => {
    const app = await createTestApp(backend.url);
    await registerUser(app);
    const wrong = await call(login, { app, body: { email: EMAIL, password: "wrong password!" } });
    const unknown = await call(login, { app, body: { email: "nobody@example.com", password: PASSWORD } });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.json.error).toEqual(unknown.json.error);
    expect(wrong.json.error.code).toBe("INVALID_CREDENTIALS");
  });

  it("locks an account after repeated failures (brute-force protection)", async () => {
    const app = await createTestApp(backend.url);
    await registerUser(app);
    for (let i = 0; i < 10; i++) {
      const r = await call(login, { app, body: { email: EMAIL, password: `wrong-password-${i}` } });
      expect(r.status).toBe(401);
    }
    const locked = await call(login, { app, body: { email: EMAIL, password: PASSWORD } });
    expect(locked.status).toBe(429);
    expect(locked.json.error.code).toBe("RATE_LIMITED");
    expect(Number(locked.headers.get("retry-after"))).toBeGreaterThan(0);
  });
});

describe("access tokens", () => {
  it("validates a token and returns the user via /me", async () => {
    const app = await createTestApp(backend.url);
    const { tokens, user } = await registerUser(app);

    const v = await call(validate, { app, body: { access_token: tokens.access_token } });
    expect(v.status).toBe(200);
    expect(v.json.data).toMatchObject({ active: true, user_id: user.user_id, app_id: app.id, session_id: tokens.session_id });

    const m = await call(me, { app, bearer: tokens.access_token });
    expect(m.status).toBe(200);
    expect(m.json.data.user).toEqual({ user_id: user.user_id, email: "alice@example.com", email_verified: false });
    expect(m.json.data.session.session_id).toBe(tokens.session_id);
  });

  it("contains the required claims", async () => {
    const app = await createTestApp(backend.url);
    const { tokens } = await registerUser(app);
    const payload = JSON.parse(Buffer.from(tokens.access_token.split(".")[1], "base64url").toString());
    expect(Object.keys(payload).sort()).toEqual(["app_id", "aud", "exp", "iat", "iss", "jti", "session_id", "sub"]);
    expect(payload.exp - payload.iat).toBe(900);
    expect(payload.aud).toBe(app.id);
    expect(payload.iss).toBe("https://auth.test.local");
  });

  it("rejects tampered tokens and requires a bearer token on /me", async () => {
    const app = await createTestApp(backend.url);
    const { tokens } = await registerUser(app);
    const [h, p, s] = tokens.access_token.split(".");
    const forgedPayload = Buffer.from(
      JSON.stringify({ ...JSON.parse(Buffer.from(p, "base64url").toString()), sub: "usr_999" }),
    ).toString("base64url");
    const forged = await call(validate, { app, body: { access_token: `${h}.${forgedPayload}.${s}` } });
    expect(forged.status).toBe(401);
    expect(forged.json.error.code).toBe("INVALID_TOKEN");

    const none = await call(validate, {
      app,
      body: { access_token: `${Buffer.from('{"alg":"none"}').toString("base64url")}.${p}.` },
    });
    expect(none.json.error.code).toBe("INVALID_TOKEN");

    const noBearer = await call(me, { app });
    expect(noBearer.status).toBe(401);
    expect(noBearer.json.error.code).toBe("MISSING_ACCESS_TOKEN");
  });

  it("rejects expired access tokens", async () => {
    const app = await createTestApp(backend.url);
    const { tokens, user } = await registerUser(app);
    const appRow = await getDb().application.findUniqueOrThrow({ where: { id: app.id } });
    const old = await signAccessToken(appRow, user.user_id, tokens.session_id, new Date(Date.now() - 16 * 60 * 1000));
    const res = await call(validate, { app, body: { access_token: old.token } });
    expect(res.status).toBe(401);
    expect(res.json.error.code).toBe("TOKEN_EXPIRED");
  });
});

describe("refresh tokens", () => {
  it("rotates refresh tokens", async () => {
    const app = await createTestApp(backend.url);
    const { tokens } = await registerUser(app);
    const r1 = await call(refresh, { app, body: { refresh_token: tokens.refresh_token } });
    expect(r1.status).toBe(200);
    const t1 = r1.json.data.tokens;
    expect(t1.refresh_token).not.toBe(tokens.refresh_token);
    expect(t1.session_id).toBe(tokens.session_id);

    const r2 = await call(refresh, { app, body: { refresh_token: t1.refresh_token } });
    expect(r2.status).toBe(200);
    const v = await call(validate, { app, body: { access_token: r2.json.data.tokens.access_token } });
    expect(v.status).toBe(200);
  });

  it("detects reuse and revokes the whole token family", async () => {
    const app = await createTestApp(backend.url);
    const { tokens } = await registerUser(app);
    const rotated = (await call(refresh, { app, body: { refresh_token: tokens.refresh_token } })).json.data.tokens;

    // Attacker replays the old token
    const replay = await call(refresh, { app, body: { refresh_token: tokens.refresh_token } });
    expect(replay.status).toBe(401);
    expect(replay.json.error.code).toBe("REFRESH_TOKEN_REUSED");

    // The legitimate (newer) token is now dead too, and so are access tokens of the session.
    const legit = await call(refresh, { app, body: { refresh_token: rotated.refresh_token } });
    expect(legit.status).toBe(401);
    expect(legit.json.error.code).toBe("SESSION_REVOKED");
    const v = await call(validate, { app, body: { access_token: rotated.access_token } });
    expect(v.json.error.code).toBe("SESSION_REVOKED");

    const session = await getDb().session.findUniqueOrThrow({ where: { id: tokens.session_id } });
    expect(session.revokedReason).toBe("refresh_token_reuse");
  });

  it("treats concurrent use of the same refresh token as reuse", async () => {
    const app = await createTestApp(backend.url);
    const { tokens } = await registerUser(app);
    const results = await Promise.all(
      [0, 1, 2].map(() => call(refresh, { app, body: { refresh_token: tokens.refresh_token } })),
    );
    expect(results.filter((r) => r.status === 200).length).toBeLessThanOrEqual(1);
    const session = await getDb().session.findUniqueOrThrow({ where: { id: tokens.session_id } });
    expect(session.revokedAt).not.toBeNull();
  });

  it("rejects expired and unknown refresh tokens", async () => {
    const app = await createTestApp(backend.url);
    const { tokens } = await registerUser(app);
    await getDb().refreshToken.updateMany({ data: { expiresAt: new Date(Date.now() - 1000) } });
    const expired = await call(refresh, { app, body: { refresh_token: tokens.refresh_token } });
    expect(expired.status).toBe(401);
    expect(expired.json.error.code).toBe("REFRESH_TOKEN_EXPIRED");

    const unknown = await call(refresh, { app, body: { refresh_token: `rt_${"A".repeat(43)}` } });
    expect(unknown.json.error.code).toBe("INVALID_REFRESH_TOKEN");
  });
});

describe("logout", () => {
  it("revokes the session: access and refresh tokens stop working", async () => {
    const app = await createTestApp(backend.url);
    const { tokens } = await registerUser(app);
    const out = await call(logout, { app, bearer: tokens.access_token, body: { refresh_token: tokens.refresh_token } });
    expect(out.status).toBe(200);
    expect(out.json.data).toEqual({ logged_out: true });

    expect((await call(validate, { app, body: { access_token: tokens.access_token } })).json.error.code).toBe(
      "SESSION_REVOKED",
    );
    expect((await call(me, { app, bearer: tokens.access_token })).status).toBe(401);
    expect((await call(refresh, { app, body: { refresh_token: tokens.refresh_token } })).json.error.code).toBe(
      "SESSION_REVOKED",
    );
  });

  it("logs out with only a refresh token, and can revoke all sessions", async () => {
    const app = await createTestApp(backend.url);
    const first = await registerUser(app);
    const second = (await call(login, { app, body: { email: EMAIL, password: PASSWORD } })).json.data.tokens;

    const viaRefresh = await call(logout, { app, body: { refresh_token: first.tokens.refresh_token } });
    expect(viaRefresh.status).toBe(200);
    expect((await call(validate, { app, body: { access_token: first.tokens.access_token } })).status).toBe(401);
    expect((await call(validate, { app, body: { access_token: second.access_token } })).status).toBe(200);

    const third = (await call(login, { app, body: { email: EMAIL, password: PASSWORD } })).json.data.tokens;
    const all = await call(logout, { app, bearer: third.access_token, body: { all_sessions: true } });
    expect(all.status).toBe(200);
    expect((await call(validate, { app, body: { access_token: second.access_token } })).status).toBe(401);
    expect((await call(validate, { app, body: { access_token: third.access_token } })).status).toBe(401);
  });

  it("requires at least one token", async () => {
    const app = await createTestApp(backend.url);
    const res = await call(logout, { app, body: {} });
    expect(res.status).toBe(400);
    expect(res.json.error.code).toBe("VALIDATION_ERROR");
  });
});
