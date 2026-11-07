# Authentication API

A lightweight, multi-tenant **authentication REST API** for developers. We handle the
security-critical parts of authentication — password hashing, credential verification,
JWT access tokens, rotating refresh tokens, sessions, logout and brute-force protection —
while **you keep full ownership of your users and your database**.

- Your user records stay in **your** database. We never ask for database credentials.
- Plaintext passwords **never** leave our API: your backend only ever receives Argon2id hashes.
- We never send emails ourselves. Optional email flows call **your** webhook; you send the email with your own provider.

Base URL (RapidAPI): `https://<your-api>.p.rapidapi.com` · Direct origin (Railway): `https://auth.xyz.com`

---

## Table of contents

1. [How it works](#1-how-it-works)
2. [Architecture](#2-architecture)
3. [Quick start for API consumers](#3-quick-start-for-api-consumers)
4. [Authentication of requests](#4-authentication-of-requests)
5. [Response format](#5-response-format)
6. [Endpoints](#6-endpoints)
7. [Error codes](#7-error-codes)
8. [Developer backend integration contract](#8-developer-backend-integration-contract)
9. [Optional email flows](#9-optional-email-flows)
9a. [Self-service application management](#9a-self-service-application-management)
10. [Example integration flow](#10-example-integration-flow)
11. [Security considerations](#11-security-considerations)
12. [Operator guide: local setup](#12-operator-guide-local-setup)
13. [Environment variables](#13-environment-variables)
14. [Database](#14-database)
15. [Provisioning applications](#15-provisioning-applications)
16. [Deploying to Railway](#16-deploying-to-railway)
17. [Publishing on RapidAPI](#17-publishing-on-rapidapi)
18. [Testing](#18-testing)
19. [Known limitations](#19-known-limitations)

---

## 1. How it works

```
 End user ──► Your frontend ──► Your backend ──(X-App-Id/X-App-Secret)──► Auth API (via RapidAPI)
                                    ▲                                          │
                                    └──────── signed integration calls ◄───────┘
                                     (user.create / user.lookup / user.get …)
```

1. Your **backend** calls the Auth API (server-to-server) with your application credentials.
2. For `register` the Auth API hashes the password with Argon2id and asks **your** backend
   (the *integration endpoint*) to store the user (`user.create`).
3. For `login` the Auth API asks your backend for the stored hash (`user.lookup`),
   verifies the password itself and issues tokens.
4. Your backend validates access tokens with `POST /api/v1/auth/validate` (or `GET /me`).

## 2. Architecture

| Component | Technology |
|---|---|
| HTTP API | Next.js 16 App Router **Route Handlers** (no pages, no UI) |
| Language | TypeScript (strict) |
| Database | PostgreSQL via Prisma 7 (`@prisma/adapter-pg`) |
| Validation | Zod (strict request schemas, strict integration response schemas) |
| Passwords | Argon2id (`m=19456 KiB, t=2, p=1` – OWASP recommendation) |
| Tokens | `jose` – HS256 JWTs with a **per-application key** |
| Rate limiting | Redis (required in production), in-memory fallback for development only |
| Outbound calls | `undici` with SSRF-safe DNS lookup, timeouts, no redirects, 64 KiB response cap |

**What we store** (PostgreSQL): applications (hashed app secret, integration URLs),
sessions, **SHA-256 hashes** of refresh tokens and one-time tokens. **What we never store**:
user passwords or password hashes, plaintext tokens, your database credentials, your email provider keys.

**Multi-tenancy.** Every application (`app_id`) is an isolated namespace:

- its own secret (`X-App-Secret`, stored hashed),
- its own JWT signing key: `HKDF-SHA256(JWT_MASTER_SECRET, app_id, "jwt-hs256:v<version>")`, and `aud = app_id`,
- its own integration signing secret: `HKDF-SHA256(INTEGRATION_MASTER_SECRET, app_id, …)`,
- sessions / refresh tokens / one-time tokens scoped by `app_id` on every query.

A token issued for application A fails signature **and** audience checks in application B.

Source layout:

```
src/app/api/v1/...        Route handlers (thin)
src/lib/auth-service.ts   Business logic for every endpoint
src/lib/sessions.ts       Sessions, refresh-token rotation & reuse detection
src/lib/jwt.ts            Access token signing/verification
src/lib/integration.ts    Developer backend client (HMAC-signed, validated)
src/lib/ssrf.ts           Outbound URL / IP validation
src/lib/rate-limit.ts     Redis / memory rate limiting
src/lib/http.ts           Envelope, body limits, CORS, security headers, gateway check
src/lib/config.ts         Environment validation (fails fast at start-up)
scripts/apps.ts           Operator CLI to provision applications
prisma/                   Schema + migrations
openapi.yaml              OpenAPI 3.0 spec (RapidAPI import)
examples/developer-backend/server.mjs   Reference implementation of the integration contract
```

## 3. Quick start for API consumers

Fully self-service, no contact with us needed:

1. Subscribe to the API on RapidAPI (any plan).
2. Create your application with **`POST /api/v1/apps`** (see [§9a](#9a-self-service-application-management)):
   ```bash
   curl -X POST https://<your-api>.p.rapidapi.com/api/v1/apps \
     -H "Content-Type: application/json" \
     -H "X-RapidAPI-Key: <your RapidAPI key>" \
     -H "X-RapidAPI-Host: <your-api>.p.rapidapi.com" \
     -d '{"name":"Acme","backend_url":"https://api.acme.com/auth-hook"}'
   ```
   You receive (**once**):
   - `app_id` (e.g. `app_6c1f…`) → header `X-App-Id`
   - `app_secret` (e.g. `sk_…`) → header `X-App-Secret` — **server-side only**
   - `integration_signing_secret` (`whsec_…`) → used by your backend to verify our calls
3. Implement the [integration contract](#8-developer-backend-integration-contract) at that HTTPS URL
   (start from `examples/developer-backend/server.mjs`).
4. Check the connection: `POST /api/v1/apps/{app_id}/test-backend` must return `"ok": true`.
5. Call `POST /api/v1/auth/register` and `POST /api/v1/auth/login` from your backend.

The application is bound to your RapidAPI account: its credentials only work with requests
made through **your** RapidAPI subscription.

```bash
curl -X POST https://<your-api>.p.rapidapi.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "X-RapidAPI-Key: <your RapidAPI key>" \
  -H "X-RapidAPI-Host: <your-api>.p.rapidapi.com" \
  -H "X-App-Id: app_6c1f0d2b9e8a7c6d5e4f3a2b" \
  -H "X-App-Secret: sk_..." \
  -H "X-End-User-IP: 203.0.113.7" \
  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'
```

## 4. Authentication of requests

Every `/api/v1/auth/*` request must include:

| Header | Required | Description |
|---|---|---|
| `X-RapidAPI-Key`, `X-RapidAPI-Host` | yes (via RapidAPI) | Your RapidAPI subscription. RapidAPI adds `X-RapidAPI-Proxy-Secret`, which the API verifies; direct calls to the origin are rejected. |
| `X-App-Id` | yes | Your application ID. |
| `X-App-Secret` | yes | Your application secret. **Never ship it to browsers or mobile apps.** |
| `Authorization: Bearer <access_token>` | `/me`, `/logout` | User access token. |
| `X-End-User-IP` | recommended | The IP of your end user. Used **only** as a per-app rate-limit key; without it all your users share your server's IP limit. |
| `Content-Type: application/json` | POST | Bodies are JSON, max 16 KiB. |

The API is designed for **server-to-server** use. CORS is disabled unless the operator
explicitly allow-lists origins.

## 5. Response format

Every response uses the same envelope:

```json
{ "success": true, "data": { "...": "..." }, "error": null }
```

```json
{
  "success": false,
  "data": null,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The request body is invalid.",
    "details": [{ "path": "email", "message": "email must be a valid email address" }]
  }
}
```

`details` is present only for validation errors. Every response carries an `X-Request-Id`
header — include it when reporting problems. `429` responses carry `Retry-After` (seconds).

## 6. Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/auth/register` | Create a user (in your backend) and start a session |
| POST | `/api/v1/auth/login` | Verify credentials and start a session |
| POST | `/api/v1/auth/refresh` | Rotate refresh token, get a new access token |
| POST | `/api/v1/auth/logout` | Revoke the current session (or all sessions) |
| GET | `/api/v1/auth/me` | Current user + session (requires Bearer token) |
| POST | `/api/v1/auth/validate` | Validate an access token (for your backend/middleware) |
| POST | `/api/v1/auth/email/verify/request` | *(optional)* Send email verification via your webhook |
| POST | `/api/v1/auth/email/verify/confirm` | *(optional)* Confirm email verification token |
| POST | `/api/v1/auth/password/reset/request` | *(optional)* Send password reset via your webhook |
| POST | `/api/v1/auth/password/reset/confirm` | *(optional)* Set a new password with a reset token |
| GET | `/api/v1/health` | Health check (no auth) |
| POST | `/api/v1/apps` | Create an application (self-service) |
| GET | `/api/v1/apps` | List your applications |
| GET | `/api/v1/apps/{app_id}` | Get one application |
| PATCH | `/api/v1/apps/{app_id}` | Update name / backend URL / email webhook URL |
| DELETE | `/api/v1/apps/{app_id}` | Delete an application and all its sessions |
| POST | `/api/v1/apps/{app_id}/rotate-secret` | Issue a new `app_secret` (old one stops working) |
| POST | `/api/v1/apps/{app_id}/rotate-integration-secret` | Issue a new `integration_signing_secret` |
| POST | `/api/v1/apps/{app_id}/test-backend` | Send a signed `app.ping` to your endpoints |

`/api/v1/auth/*` endpoints need `X-App-Id` + `X-App-Secret`. `/api/v1/apps*` endpoints need only
your RapidAPI subscription (no app credentials).

### Token bundle

`register`, `login` and `refresh` return:

```json
{
  "token_type": "Bearer",
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFwcF82YzFm…",
  "access_token_expires_at": "2026-11-07T18:06:41.000Z",
  "expires_in": 900,
  "refresh_token": "rt_Q2x1c3RlcjQ…",
  "refresh_token_expires_at": "2026-12-07T17:51:41.172Z",
  "session_id": "3bb8e5ba-df6c-411d-9dbb-dd1e71c512ad"
}
```

- **Access token**: JWT (HS256), valid **15 minutes**. Claims: `sub` (user ID from your backend),
  `app_id`, `session_id`, `iat`, `exp`, `iss` (our public URL), `aud` (= `app_id`), `jti`.
  It is signed with a key only the Auth API knows — validate it with `/validate`.
- **Refresh token**: opaque random string (256 bits), valid 30 days, **single use**.
  Every refresh returns a new one. Store it securely (e.g. httpOnly, Secure, SameSite cookie set by your backend).

### POST /api/v1/auth/register

Request:

```json
{ "email": "alice@example.com", "password": "correct horse battery staple" }
```

Rules: email ≤ 254 chars (trimmed, lower-cased); password 8–128 chars. Unknown fields are rejected.

Response `201`:

```json
{
  "success": true,
  "data": {
    "user": { "user_id": "user_42", "email": "alice@example.com", "email_verified": false },
    "tokens": { "token_type": "Bearer", "access_token": "…", "expires_in": 900, "refresh_token": "rt_…", "…": "…" }
  },
  "error": null
}
```

Errors: `400 VALIDATION_ERROR`, `409 EMAIL_ALREADY_REGISTERED`, `429 RATE_LIMITED`, `502/504` integration errors.

### POST /api/v1/auth/login

Request: `{ "email": "alice@example.com", "password": "correct horse battery staple" }`

Response `200`: same shape as register (`user.email_verified` is `null` if your backend does not report it).

Errors: `401 INVALID_CREDENTIALS` (identical for unknown email and wrong password),
`429 RATE_LIMITED` (after 10 failed attempts per account per 15 minutes, or 30 attempts per IP per 15 minutes).

### POST /api/v1/auth/refresh

Request: `{ "refresh_token": "rt_…" }` → Response `200`: `{ "tokens": { … } }`

Errors: `401 INVALID_REFRESH_TOKEN`, `401 REFRESH_TOKEN_EXPIRED`, `401 SESSION_REVOKED`,
`401 REFRESH_TOKEN_REUSED` — a token that was already exchanged was presented again. This
indicates theft; **the whole session is revoked** and the user must log in again.
Do not send parallel refresh requests with the same token.

### POST /api/v1/auth/logout

Any of:

```json
{ "refresh_token": "rt_…" }
```

or header `Authorization: Bearer <access_token>` with `{}` (revokes that session), or
`Authorization: Bearer <access_token>` with `{ "all_sessions": true }` (revokes every session of the user in your app).

Response `200`: `{ "logged_out": true }`. Unknown refresh tokens are ignored (idempotent).
After logout, access tokens of the session fail `/validate` and `/me` immediately.

### GET /api/v1/auth/me

Header `Authorization: Bearer <access_token>`. Calls your backend (`user.get`) for fresh data.

```json
{
  "success": true,
  "data": {
    "user": { "user_id": "user_42", "email": "alice@example.com", "email_verified": true },
    "session": {
      "session_id": "3bb8e5ba-df6c-411d-9dbb-dd1e71c512ad",
      "created_at": "2026-11-07T17:51:41.195Z",
      "expires_at": "2026-12-07T17:51:41.172Z",
      "access_token_expires_at": "2026-11-07T18:06:41.000Z"
    }
  },
  "error": null
}
```

If your backend returns 404 for the user, all their sessions are revoked and `401 SESSION_REVOKED` is returned.

### POST /api/v1/auth/validate

Request: `{ "access_token": "eyJ…" }`. Verifies signature, issuer, audience, expiry **and**
that the session is still active (not logged out / revoked).

```json
{
  "success": true,
  "data": {
    "active": true,
    "user_id": "user_42",
    "app_id": "app_6c1f0d2b9e8a7c6d5e4f3a2b",
    "session_id": "3bb8e5ba-df6c-411d-9dbb-dd1e71c512ad",
    "issued_at": "2026-11-07T17:51:41.000Z",
    "expires_at": "2026-11-07T18:06:41.000Z",
    "session_expires_at": "2026-12-07T17:51:41.172Z"
  },
  "error": null
}
```

Errors: `401 INVALID_TOKEN`, `401 TOKEN_EXPIRED`, `401 SESSION_REVOKED`.
Always trust `user_id` from this response, never a user ID sent by a client.

### GET /api/v1/health

No authentication, not behind the gateway check. `200` when PostgreSQL and the rate limiter are reachable, otherwise `503`.

```json
{ "success": true, "data": { "status": "ok", "version": "v1", "checks": { "database": "ok", "rate_limiter": "ok", "rate_limiter_store": "redis" } }, "error": null }
```

## 7. Error codes

| HTTP | Code | Meaning |
|---|---|---|
| 400 | `VALIDATION_ERROR` | Body failed validation (see `details`) |
| 400 | `INVALID_JSON` | Body is not valid JSON |
| 400 | `INVALID_ONE_TIME_TOKEN` | Email/reset token invalid, expired or used |
| 400 | `INVALID_INTEGRATION_URL` | Backend/email URL not allowed (see `details`) |
| 401 | `MISSING_DEVELOPER_IDENTITY` | `/apps` called without a RapidAPI user |
| 401 | `MISSING_APP_CREDENTIALS` | `X-App-Id` / `X-App-Secret` missing |
| 401 | `INVALID_APP_CREDENTIALS` | Unknown app, wrong secret, or app disabled |
| 401 | `INVALID_CREDENTIALS` | Wrong email or password |
| 401 | `MISSING_ACCESS_TOKEN` | Bearer token required |
| 401 | `INVALID_TOKEN` | Access token malformed, forged, or for another app |
| 401 | `TOKEN_EXPIRED` | Access token expired → call `/refresh` |
| 401 | `SESSION_REVOKED` | Session logged out, revoked or expired |
| 401 | `INVALID_REFRESH_TOKEN` | Unknown refresh token |
| 401 | `REFRESH_TOKEN_EXPIRED` | Refresh token expired → log in again |
| 401 | `REFRESH_TOKEN_REUSED` | Reuse detected, session revoked → log in again |
| 403 | `PROXY_AUTH_FAILED` | Request did not come through RapidAPI |
| 403 | `APP_ACCESS_DENIED` | App is bound to a different RapidAPI user |
| 403 | `APP_LIMIT_REACHED` | Maximum number of applications per developer reached |
| 404 | `NOT_FOUND` | Unknown endpoint, or an application that is not yours |
| 409 | `EMAIL_ALREADY_REGISTERED` | Your backend reported the email exists |
| 413 | `PAYLOAD_TOO_LARGE` | Body > 16 KiB |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Content-Type is not `application/json` |
| 429 | `RATE_LIMITED` | Too many requests, see `Retry-After` |
| 500 | `INTERNAL_ERROR` | Unexpected error (report `X-Request-Id`) |
| 501 | `FEATURE_NOT_CONFIGURED` | Email webhook not configured for this app |
| 502 | `INTEGRATION_ERROR` | Your backend failed or violated the contract |
| 503 | `SERVICE_UNAVAILABLE` | Database / rate limiter unavailable |
| 504 | `INTEGRATION_TIMEOUT` | Your backend did not answer within 5 s |

## 8. Developer backend integration contract

You expose **one HTTPS endpoint** (your *backend URL*, e.g. `https://api.acme.com/auth-hook`).
We call it with `POST` and a JSON body:

```json
{
  "action": "user.create",
  "app_id": "app_6c1f0d2b9e8a7c6d5e4f3a2b",
  "request_id": "6b0f4c1e-6f9e-4a63-9b8e-2a3c5d7e9f10",
  "data": { "...action specific..." }
}
```

### Request authentication (you MUST verify this)

Headers sent with every call:

| Header | Example |
|---|---|
| `X-AuthAPI-App-Id` | `app_6c1f0d2b9e8a7c6d5e4f3a2b` |
| `X-AuthAPI-Action` | `user.lookup` |
| `X-AuthAPI-Request-Id` | `6b0f4c1e-…` (unique per call; may be used for replay de-duplication) |
| `X-AuthAPI-Timestamp` | `1762537901` (Unix seconds) |
| `X-AuthAPI-Signature` | `v1=5d41402abc4b2a76b9719d911017c592…` |

```
signature = "v1=" + hex( HMAC_SHA256( integration_signing_secret, timestamp + "." + raw_request_body ) )
```

Reject the request (HTTP 401) if the signature does not match (use a constant-time comparison)
or the timestamp is more than 300 seconds from your clock. Compute the HMAC over the **raw** body bytes,
before JSON parsing.

```js
import { createHmac, timingSafeEqual } from "node:crypto";
function verify(req, rawBody, secret) {
  const ts = req.headers["x-authapi-timestamp"];
  const sig = req.headers["x-authapi-signature"] ?? "";
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;
  const expected = "v1=" + createHmac("sha256", secret).update(`${ts}.${rawBody}`).digest("hex");
  return sig.length === expected.length && timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}
```

### Response rules

- Respond within **5 seconds**, with `Content-Type: application/json` when there is a body, body ≤ 64 KiB.
- **Do not redirect** (3xx is treated as an error).
- Extra fields in your responses are ignored; missing/invalid required fields cause `502 INTEGRATION_ERROR`.
- `user_id`: string, 1–128 chars, `[A-Za-z0-9._:@|-]`. It becomes the JWT `sub`.
- `password_hash`: store and return **exactly** what we sent you (an Argon2id PHC string, `$argon2id$v=19$…`).

### Actions

#### `user.create` (required)

```json
{ "action": "user.create", "app_id": "app_…", "request_id": "…",
  "data": { "email": "alice@example.com", "password_hash": "$argon2id$v=19$m=19456,t=2,p=1$…" } }
```

| Your response | Meaning |
|---|---|
| `201` (or `200`) `{ "user_id": "user_42", "email": "alice@example.com" }` | created |
| `409` (any body) | email already exists |

The returned `email` must equal the requested email (case-insensitive).

#### `user.lookup` (required)

```json
{ "action": "user.lookup", "data": { "email": "alice@example.com" } }
```

| Your response | Meaning |
|---|---|
| `200` `{ "user_id": "user_42", "email": "alice@example.com", "password_hash": "$argon2id$…", "email_verified": true }` | found (`email_verified` optional) |
| `404` | not found |

We verify the password; you never see it. Emails are sent normalized (trimmed, lower-case) —
look them up case-insensitively.

#### `user.get` (required, used by `/me`)

```json
{ "action": "user.get", "data": { "user_id": "user_42" } }
```

`200 { "user_id": "user_42", "email": "alice@example.com", "email_verified": true }` or `404`.

#### `app.ping` (required for `test-backend`)

`data: {}` → any `2xx` after verifying the signature. Sent only when you call
`POST /api/v1/apps/{app_id}/test-backend` (to both the backend URL and the email webhook URL).

#### `user.mark_email_verified` (only with email features)

`data: { "user_id": "user_42", "email": "alice@example.com" }` → `204`/`200`, or `404` if the user does not exist
or the email no longer matches.

#### `user.update_password` (only with email features)

`data: { "user_id": "user_42", "password_hash": "$argon2id$…" }` → `204`/`200`, or `404`.

#### `email.send` (sent to your optional **email webhook URL**)

```json
{ "action": "email.send", "app_id": "app_…", "request_id": "…",
  "data": {
    "type": "email_verification",
    "to": "alice@example.com",
    "user_id": "user_42",
    "token": "ev_0p9C…",
    "expires_at": "2026-11-08T17:51:41.000Z"
  } }
```

`type` is `email_verification` (token valid 24 h) or `password_reset` (token valid 1 h).
Respond `200/201/202/204` and send the email with your own provider. Build the link in your app,
e.g. `https://app.acme.com/reset-password?token=<token>`. The token is single-use, signed in the same
way, and **never** returned by our public API.

A complete runnable example is in [`examples/developer-backend/server.mjs`](examples/developer-backend/server.mjs).

## 9. Optional email flows

Enabled per application when the operator configures an **email webhook URL**. Without it,
these endpoints return `501 FEATURE_NOT_CONFIGURED` and everything else works normally.

| Step | Call |
|---|---|
| 1. Request | `POST /api/v1/auth/email/verify/request` `{ "email": "…" }` → always `202 { "accepted": true }` (no account enumeration) |
| 2. Delivery | We call your webhook with `email.send` (`type: "email_verification"`) |
| 3. User clicks | Your frontend reads `token` from the link and your backend calls … |
| 4. Confirm | `POST /api/v1/auth/email/verify/confirm` `{ "token": "ev_…" }` → `200 { "user_id", "email", "email_verified": true }` (we call `user.mark_email_verified`) |

Password reset is identical with `/password/reset/request` and
`POST /api/v1/auth/password/reset/confirm` `{ "token": "pr_…", "new_password": "…" }` →
`200 { "password_reset": true, "sessions_revoked": 2 }`. We hash the new password, call
`user.update_password`, and revoke **all** of the user's sessions.

Only the most recently issued token per user and purpose is valid. If your backend fails during
confirmation, the token stays usable until it expires.

## 9a. Self-service application management

Developers create and manage their own applications — no manual provisioning.

**How identity works.** RapidAPI authenticates the subscriber (`X-RapidAPI-Key`) and forwards the
request with `X-RapidAPI-User` (the subscriber's username) and `X-RapidAPI-Proxy-Secret`. The API
verifies the proxy secret, so `X-RapidAPI-User` can be trusted; requests that bypass RapidAPI are
rejected (`403 PROXY_AUTH_FAILED`). Every application is **owned by and bound to** that RapidAPI
user: only the owner can see or change it, and its `X-App-Id`/`X-App-Secret` only work on
requests made through the owner's subscription (`403 APP_ACCESS_DENIED` otherwise).
If the server has no `RAPIDAPI_PROXY_SECRET` configured, these endpoints are disabled.

**Limits.** `MAX_APPS_PER_DEVELOPER` applications per RapidAPI user (default 5), 10 creations/hour,
120 management calls/hour, 30 connection tests/hour.

**URL rules** (`backend_url`, `email_webhook_url`): `https://` only, public domain name that resolves to
public IP addresses only, no credentials, no fragment, not this API's own domain and not `rapidapi.com`.
Violations return `400 INVALID_INTEGRATION_URL` with the reason in `details`.

### POST /api/v1/apps

```json
{
  "name": "Acme",
  "backend_url": "https://api.acme.com/auth-hook",
  "email_webhook_url": "https://api.acme.com/auth-email"
}
```

`email_webhook_url` is optional. Response `201`:

```json
{
  "success": true,
  "data": {
    "app": {
      "app_id": "app_6c1f0d2b9e8a7c6d5e4f3a2b",
      "name": "Acme",
      "backend_url": "https://api.acme.com/auth-hook",
      "email_webhook_url": "https://api.acme.com/auth-email",
      "is_active": true,
      "integration_secret_version": 1,
      "created_at": "2026-11-07T19:46:27.611Z",
      "updated_at": "2026-11-07T19:46:27.611Z"
    },
    "credentials": {
      "app_secret": "sk_…",
      "integration_signing_secret": "whsec_…",
      "note": "Store these secrets now. They are shown only once; use the rotate endpoints to replace them."
    }
  },
  "error": null
}
```

### GET /api/v1/apps · GET /api/v1/apps/{app_id}

Returns `{ "apps": [ …app… ], "limit": 5 }` / `{ "app": { … } }`. Secrets are never returned.
Applications of other developers return `404`.

### PATCH /api/v1/apps/{app_id}

Any of `name`, `backend_url`, `email_webhook_url` (`null` disables the email features). → `{ "app": { … } }`

### DELETE /api/v1/apps/{app_id}

Deletes the application with all its sessions and tokens. → `{ "deleted": true, "app_id": "app_…" }`

### POST /api/v1/apps/{app_id}/rotate-secret

→ `{ "app_id": "app_…", "app_secret": "sk_…" }`. The old secret stops working **immediately**:
deploy the new one to your backend right after rotating.

### POST /api/v1/apps/{app_id}/rotate-integration-secret

→ `{ "app_id": "app_…", "integration_signing_secret": "whsec_…", "integration_secret_version": 2 }`.
From now on calls to your backend are signed with the new secret. During the switch, let your
backend accept both the old and the new secret, then remove the old one.

### POST /api/v1/apps/{app_id}/test-backend

Sends a signed `app.ping` to your backend URL (and email webhook URL, if set):

```json
{
  "success": true,
  "data": {
    "ok": false,
    "backend": {
      "ok": false,
      "status": 401,
      "latency_ms": 42,
      "error": "Your endpoint rejected the request: check signature verification and the integration signing secret."
    },
    "email_webhook": null
  },
  "error": null
}
```

## 10. Example integration flow

```text
Sign-up
  browser ──POST /signup {email,password}──► your backend
  your backend ──POST /api/v1/auth/register──► Auth API
  Auth API ──user.create {email, password_hash}──► your backend (stores user)
  Auth API ──► your backend: {user, tokens}
  your backend: set refresh_token in httpOnly cookie, return access_token to browser

Authenticated request
  browser ──GET /orders  Authorization: Bearer <access_token>──► your backend
  your backend ──POST /api/v1/auth/validate {access_token}──► Auth API
     200 → use data.user_id;  401 TOKEN_EXPIRED → client refreshes

Refresh
  your backend ──POST /api/v1/auth/refresh {refresh_token from cookie}──► Auth API
  store the NEW refresh_token (old one is now invalid)

Logout
  your backend ──POST /api/v1/auth/logout {refresh_token} + Bearer──► Auth API
```

Tip: cache successful `/validate` results for a few seconds in your backend if you need lower latency;
the cache duration is the maximum delay before a logout takes effect.

## 11. Security considerations

- **Passwords**: Argon2id (19 MiB, t=2, p=1); 8–128 chars; never logged, never sent to your backend.
  Unknown-email logins run a dummy Argon2 verification to equalize timing.
- **Account enumeration**: login errors are generic; email/reset request endpoints always return `202`.
  Registration necessarily reports `409` for existing emails (standard trade-off; rate-limited).
- **Brute force**: per-account failure lockout (10 / 15 min) + per-IP limits on register (10/h),
  login (30 / 15 min), refresh (60 / 15 min), email requests (5/h per account, 20/h per IP).
  Production requires Redis; if Redis is unreachable, protected endpoints fail **closed** (`503`).
- **Tokens**: 15-minute HS256 access tokens with per-app keys, `iss`/`aud`/`exp` verified, `alg` pinned.
  Refresh tokens are 256-bit random, stored as SHA-256 hashes, rotated on every use, reuse revokes the family.
  Session state is checked on every validation, so logout is immediate.
- **Application isolation**: per-app keys, `aud`, and `app_id` checks on every DB lookup.
  Self-service apps are bound to their owner's RapidAPI user (`X-RapidAPI-User`, trusted only after
  the proxy-secret check), so leaked app credentials are useless from another subscription.
- **Self-service provisioning**: no anonymous registration; creation requires a RapidAPI subscription,
  is limited per developer (serialized with a Postgres advisory lock) and rate-limited.
- **Gateway**: `X-RapidAPI-Proxy-Secret` is verified (constant-time) on every API call in production.
  A RapidAPI key alone is not trusted.
- **Integration calls**: HMAC-SHA256 signed with timestamps; HTTPS only; URLs validated at provisioning and
  at call time; DNS results checked at connect time (blocks private, loopback, link-local, CGNAT,
  metadata and reserved ranges, IPv4-mapped IPv6, DNS rebinding); redirects not followed; 5 s timeout;
  64 KiB response cap; strict response validation. Integration URLs can only be set by the
  authenticated app owner (through RapidAPI) or the operator CLI, and never point at this API itself.
- **HTTP hardening**: 16 KiB body limit, `application/json` only, strict schemas (unknown fields rejected),
  `Cache-Control: no-store`, HSTS, `nosniff`, `X-Frame-Options: DENY`, CSP `default-src 'none'`,
  no `X-Powered-By`, strict CORS (off by default, no wildcard).
- **Logging**: structured JSON; keys matching password/secret/token/hash/authorization are redacted;
  request bodies are never logged.
- **Secrets**: only via environment variables; validated at start-up (length, entropy, placeholders,
  production requirements). The server refuses to start if misconfigured.

## 12. Operator guide: local setup

Requirements: Node.js 22.19+, PostgreSQL 14+, optionally Redis.

```bash
npm install
cp .env.example .env.local      # fill JWT_MASTER_SECRET, INTEGRATION_MASTER_SECRET, DATABASE_URL
npx prisma migrate deploy       # or: npm run db:migrate:dev while changing the schema
npm run dev                     # http://localhost:3000/api/v1/health
```

`prisma` and the CLI read variables from the process environment; export them in your shell
(e.g. `set -a; source .env.local; set +a`).

For local integration testing set `INTEGRATION_ALLOW_PRIVATE_URLS=true` and run the example backend:

```bash
INTEGRATION_SIGNING_SECRET=whsec_... node examples/developer-backend/server.mjs
```

## 13. Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | **yes** | – | PostgreSQL connection string (Railway: `${{Postgres.DATABASE_URL}}`) |
| `JWT_MASTER_SECRET` | **yes** | – | ≥ 32 chars, random. Derives per-app JWT keys. Changing it invalidates all access tokens. |
| `INTEGRATION_MASTER_SECRET` | **yes** | – | ≥ 32 chars, random, different from the JWT secret. Derives per-app integration signing secrets. Changing it changes every app's `whsec_` secret. |
| `JWT_ISSUER` | **prod** | `http://localhost:3000` | Public HTTPS base URL, e.g. `https://auth.xyz.com` (`iss` claim) |
| `REDIS_URL` | **prod** | – | Shared rate-limit store (Railway: `${{Redis.REDIS_URL}}`) |
| `RAPIDAPI_PROXY_SECRET` | **prod** | – | From RapidAPI Studio; verified on every API request |
| `NODE_ENV` | no | `development` | `next start` sets `production` |
| `ACCESS_TOKEN_TTL_SECONDS` | no | `900` | 60–3600 |
| `REFRESH_TOKEN_TTL_DAYS` | no | `30` | 1–365 |
| `INTEGRATION_TIMEOUT_MS` | no | `5000` | 500–15000 |
| `MAX_APPS_PER_DEVELOPER` | no | `5` | Self-service applications per RapidAPI user (1–1000) |
| `CORS_ALLOWED_ORIGINS` | no | empty | Comma-separated exact origins; `*` is rejected |
| `LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, `error`, `silent` |
| `INTEGRATION_ALLOW_PRIVATE_URLS` | no | `false` | **Dev/test only**: allow `http://` and private hosts. Refused in production. |
| `PORT` | no | `3000` | Set automatically by Railway |

Generate secrets: `openssl rand -base64 48`.

## 14. Database

Tables (see `prisma/schema.prisma`): `applications`, `sessions`, `refresh_tokens`, `one_time_tokens`.
Migrations live in `prisma/migrations` and are applied with `npm run db:migrate`
(`prisma migrate deploy`). On Railway this runs automatically as the pre-deploy command.

Housekeeping (expired/revoked rows older than N days): `npm run apps -- cleanup --days 7`
(schedule it, e.g. as a Railway cron service, daily).

## 15. Provisioning applications

Developers normally create applications themselves through `POST /api/v1/apps`
([§9a](#9a-self-service-application-management)). There is **no anonymous endpoint**: creation
requires a RapidAPI subscription.

The operator CLI remains for support and administration (e.g. disabling an abusive app, creating
apps for customers outside RapidAPI, cleanup). Run it with the production environment variables:

```bash
npm run apps -- create --name "Acme" \
  --backend-url https://api.acme.com/auth-hook \
  --email-webhook-url https://api.acme.com/auth-email \
  --rapidapi-user acme_rapidapi_username
```

Output (secrets are shown **once**):

```json
{
  "app_id": "app_6c1f0d2b9e8a7c6d5e4f3a2b",
  "name": "Acme",
  "backend_url": "https://api.acme.com/auth-hook",
  "email_webhook_url": "https://api.acme.com/auth-email",
  "rapidapi_user": "acme_rapidapi_username",
  "is_active": true,
  "app_secret": "sk_…",
  "integration_signing_secret": "whsec_…"
}
```

Other commands: `list`, `show`, `update`, `rotate-secret`, `rotate-integration-secret`,
`rotate-jwt-key`, `disable`, `enable`, `cleanup` (see `scripts/apps.ts`).
`disable` is the operator's kill switch: developers cannot re-enable a disabled app themselves.
Apps created with the CLI without `--rapidapi-user` are not visible through `/api/v1/apps`.

On Railway: `railway ssh` into the service and run the command there, or run it locally with
`railway run npm run apps -- …` (uses the service variables; requires the database to be reachable
from your machine, e.g. via `DATABASE_PUBLIC_URL`).

## 16. Deploying to Railway

1. Push this repository to GitHub.
2. In Railway: **New Project → Deploy from GitHub repo** → select the repo.
3. Add **PostgreSQL** (`+ New → Database → PostgreSQL`) and **Redis** (`+ New → Database → Redis`).
4. In the API service → **Variables**:
   ```
   DATABASE_URL=${{Postgres.DATABASE_URL}}
   REDIS_URL=${{Redis.REDIS_URL}}
   JWT_MASTER_SECRET=<openssl rand -base64 48>
   INTEGRATION_MASTER_SECRET=<openssl rand -base64 48, different>
   JWT_ISSUER=https://auth.xyz.com
   RAPIDAPI_PROXY_SECRET=<from RapidAPI Studio, see §17>
   ```
5. `railway.json` already configures: build `npm run build` (Prisma generate + Next build),
   pre-deploy `npm run db:migrate`, start `npm run start`, health check `/api/v1/health`.
   Node 22 is selected from `package.json#engines`.
6. **Settings → Networking → Custom Domain** → `auth.xyz.com`, add the CNAME at your DNS provider.
7. Deploy. Verify: `curl https://auth.xyz.com/api/v1/health`.
8. Provision your first application ([§15](#15-provisioning-applications)).

If a required variable is missing the service logs `FATAL: Invalid configuration` and stops — fix the
variable and redeploy. Run one or more replicas; all state is in PostgreSQL/Redis.

## 17. Publishing on RapidAPI

1. Create a RapidAPI provider account → **RapidAPI Studio → Add API Project**.
2. **Definitions → Import** `openapi.yaml` from this repository (OpenAPI 3.0).
3. **Settings / Gateway → Base URL**: `https://auth.xyz.com` (your Railway domain).
4. **Gateway / Security**: copy the **X-RapidAPI-Proxy-Secret** value, set it as
   `RAPIDAPI_PROXY_SECRET` on Railway and redeploy. Direct requests without it get `403`.
5. Add `X-App-Id`, `X-App-Secret` (and `X-End-User-IP`) as header parameters if they are not
   imported automatically (they are defined in the spec). Optionally enable *Gateway → Firewall*
   so only the RapidAPI gateway can reach the origin.
6. **Monetize → Plans**: e.g. Free (low quota), Pro, Ultra. Quotas are enforced by RapidAPI;
   our own rate limits protect against brute force.
7. **Docs**: paste sections 3–10 of this README into the API's *About / Tutorials* tab,
   including the onboarding instructions for obtaining an `app_id` (see limitations).
8. In the API description, point new users to `POST /api/v1/apps` as the first step
   (Quick start, [§3](#3-quick-start-for-api-consumers)).
9. Test every endpoint from the RapidAPI playground (start with `POST /api/v1/apps`), then set the
   API to **Public**.

## 18. Testing

```bash
# needs PostgreSQL; uses database authapi_test by default
TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:5432/authapi_test \
TEST_REDIS_URL=redis://127.0.0.1:6379 npm test
```

The suite runs the real route handlers against PostgreSQL and a mock developer backend that
verifies request signatures. It covers registration (incl. duplicates), login (incl. wrong password
and lockout), token validation and claims, forged / `alg:none` / expired tokens, refresh rotation,
reuse and concurrent reuse detection, logout and logout-all, application isolation, RapidAPI proxy
secret and user binding, invalid bodies (schema, JSON, content type, size), integration failures
(5xx, timeout, invalid shape, HTML, non-Argon2 hash, redirects), email verification and password
reset flows, SSRF rules, configuration validation, log redaction, the Redis store, and self-service
app management (gateway/identity checks, ownership isolation, per-developer limit incl. concurrent
creation, URL rules, secret rotation, connection test, deletion cascade).

Other checks: `npm run typecheck`, `npm run lint`, `npm run build`.

## 19. Known limitations

- Self-service management works only through RapidAPI (identity = RapidAPI user). Customers outside
  RapidAPI are provisioned with the operator CLI.
- Rotating `app_secret` has no grace period: the old secret stops working immediately.
- Access tokens are HS256 with server-only keys, so consumers validate them via `/validate`
  (one network call). JWKS/RS256 offline validation is not implemented.
- Registration reveals whether an email exists (`409`), as most sign-up flows do.
- Concurrent refreshes with the same refresh token are treated as reuse and revoke the session.
- Expired rows are only removed by the `cleanup` command — schedule it.
