import { createServer, IncomingMessage, Server, ServerResponse } from "node:http";
import { AddressInfo } from "node:net";
import { afterAll, beforeEach } from "vitest";
import { generateAppId, generateAppSecret, hashAppSecret, integrationSigningSecret } from "@/lib/apps";
import { resetConfigForTests } from "@/lib/config";
import { hmacSha256Hex, safeEqual } from "@/lib/crypto";
import { disconnectDb, getDb } from "@/lib/db";
import { resetIntegrationAgent } from "@/lib/integration";
import { MemoryCounterStore, setCounterStoreForTests } from "@/lib/rate-limit";

// ---------------------------------------------------------------------------
// Mock developer backend implementing the integration contract.
// It verifies the HMAC signature exactly like a real developer backend should.
// ---------------------------------------------------------------------------

export type BackendMode = "ok" | "error500" | "timeout" | "invalid-shape" | "bad-hash" | "html" | "redirect" | "bad-signature-check";

interface StoredUser {
  user_id: string;
  email: string;
  password_hash: string;
  email_verified: boolean;
}

export interface SentEmail {
  type: string;
  to: string;
  user_id: string;
  token: string;
  expires_at: string;
}

export class MockBackend {
  server!: Server;
  url = "";
  mode: BackendMode = "ok";
  /** users[app_id][email] */
  users = new Map<string, Map<string, StoredUser>>();
  emails: SentEmail[] = [];
  rawBodies: string[] = [];
  signatureFailures = 0;
  private seq = 0;

  async start() {
    this.server = createServer((req, res) => void this.handle(req, res));
    await new Promise<void>((r) => this.server.listen(0, "127.0.0.1", () => r()));
    this.url = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }

  async stop() {
    this.server.closeAllConnections();
    await new Promise<void>((r) => this.server.close(() => r()));
  }

  reset() {
    this.mode = "ok";
    this.users.clear();
    this.emails = [];
    this.rawBodies = [];
    this.signatureFailures = 0;
    this.seq = 0;
  }

  usersOf(appId: string) {
    if (!this.users.has(appId)) this.users.set(appId, new Map());
    return this.users.get(appId)!;
  }

  private send(res: ServerResponse, status: number, body?: unknown) {
    if (body === undefined) {
      res.writeHead(status).end();
      return;
    }
    res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  }

  private async handle(req: IncomingMessage, res: ServerResponse) {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks).toString("utf8");
    this.rawBodies.push(raw);

    if (this.mode === "timeout") return; // never answer
    if (this.mode === "error500") return this.send(res, 500, { error: "boom" });
    if (this.mode === "html") return void res.writeHead(200, { "content-type": "text/html" }).end("<html></html>");
    if (this.mode === "redirect") return void res.writeHead(302, { location: "http://169.254.169.254/latest" }).end();

    // --- signature verification (what developers must implement) ---
    const body = JSON.parse(raw) as { action: string; app_id: string; data: Record<string, string> };
    const ts = String(req.headers["x-authapi-timestamp"] ?? "");
    const sig = String(req.headers["x-authapi-signature"] ?? "");
    const secret = integrationSigningSecret({ id: body.app_id, integrationSecretVersion: 1 });
    const expected = `v1=${hmacSha256Hex(secret, `${ts}.${raw}`)}`;
    const fresh = Math.abs(Date.now() / 1000 - Number(ts)) < 300;
    if (!fresh || !safeEqual(sig, expected) || req.headers["x-authapi-app-id"] !== body.app_id) {
      this.signatureFailures++;
      return this.send(res, 401, { error: "bad signature" });
    }

    const users = this.usersOf(body.app_id);
    const d = body.data;
    switch (body.action) {
      case "user.create": {
        if (users.has(d.email)) return this.send(res, 409, { error: "exists" });
        const user = { user_id: `usr_${++this.seq}`, email: d.email, password_hash: d.password_hash, email_verified: false };
        users.set(d.email, user);
        if (this.mode === "invalid-shape") return this.send(res, 201, { id: 1 });
        return this.send(res, 201, { user_id: user.user_id, email: user.email });
      }
      case "user.lookup": {
        const u = users.get(d.email);
        if (!u) return this.send(res, 404, { error: "not_found" });
        if (this.mode === "bad-hash") return this.send(res, 200, { ...u, password_hash: "plaintext-or-md5" });
        if (this.mode === "invalid-shape") return this.send(res, 200, { user: u });
        return this.send(res, 200, u);
      }
      case "user.get": {
        const u = [...users.values()].find((x) => x.user_id === d.user_id);
        if (!u) return this.send(res, 404, { error: "not_found" });
        return this.send(res, 200, { user_id: u.user_id, email: u.email, email_verified: u.email_verified });
      }
      case "user.mark_email_verified": {
        const u = [...users.values()].find((x) => x.user_id === d.user_id);
        if (!u || u.email !== d.email) return this.send(res, 404, { error: "not_found" });
        u.email_verified = true;
        return this.send(res, 204);
      }
      case "user.update_password": {
        const u = [...users.values()].find((x) => x.user_id === d.user_id);
        if (!u) return this.send(res, 404, { error: "not_found" });
        u.password_hash = d.password_hash;
        return this.send(res, 204);
      }
      case "email.send": {
        this.emails.push(d as unknown as SentEmail);
        return this.send(res, 202, { queued: true });
      }
      default:
        return this.send(res, 400, { error: "unknown action" });
    }
  }
}

// ---------------------------------------------------------------------------
// Test applications & request helpers
// ---------------------------------------------------------------------------

export interface TestApp {
  id: string;
  secret: string;
}

export async function createTestApp(
  backendUrl: string,
  opts: { emailWebhook?: boolean; rapidApiUser?: string; isActive?: boolean } = {},
): Promise<TestApp> {
  const secret = generateAppSecret();
  const id = generateAppId();
  await getDb().application.create({
    data: {
      id,
      name: `test ${id}`,
      secretHash: hashAppSecret(secret),
      backendUrl: `${backendUrl}/auth-hook`,
      emailWebhookUrl: opts.emailWebhook ? `${backendUrl}/email-hook` : null,
      rapidApiUser: opts.rapidApiUser ?? null,
      isActive: opts.isActive ?? true,
    },
  });
  return { id, secret };
}

type Handler = (req: Request) => Promise<Response>;

export async function call(
  handler: Handler,
  opts: {
    app?: TestApp;
    body?: unknown;
    rawBody?: string;
    method?: string;
    bearer?: string;
    headers?: Record<string, string>;
    path?: string;
  } = {},
) {
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.app) {
    headers["x-app-id"] = opts.app.id;
    headers["x-app-secret"] = opts.app.secret;
  }
  if (opts.bearer) headers.authorization = `Bearer ${opts.bearer}`;
  let body: string | undefined;
  if (opts.rawBody !== undefined) body = opts.rawBody;
  else if (opts.body !== undefined) body = JSON.stringify(opts.body);
  if (body !== undefined && !headers["content-type"]) headers["content-type"] = "application/json";
  const req = new Request(`http://localhost${opts.path ?? "/api/v1/test"}`, {
    method: opts.method ?? (body !== undefined ? "POST" : "GET"),
    headers,
    body,
  });
  const res = await handler(req);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const json = (await res.json().catch(() => null)) as any;
  return { status: res.status, headers: res.headers, json };
}

export async function truncateAll() {
  await getDb().$executeRawUnsafe(
    'TRUNCATE TABLE "refresh_tokens", "sessions", "one_time_tokens", "applications" RESTART IDENTITY CASCADE',
  );
}

/** Standard per-file lifecycle: fresh DB tables, fresh rate limiter, mock backend running. */
export function setupTestContext() {
  const backend = new MockBackend();
  let started = false;
  beforeEach(async () => {
    if (!started) {
      await backend.start();
      started = true;
    }
    resetConfigForTests();
    await resetIntegrationAgent();
    setCounterStoreForTests(new MemoryCounterStore());
    backend.reset();
    await truncateAll();
  });
  afterAll(async () => {
    if (started) await backend.stop();
    await resetIntegrationAgent();
    await disconnectDb();
  });
  return backend;
}
