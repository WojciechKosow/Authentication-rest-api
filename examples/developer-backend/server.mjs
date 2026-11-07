/**
 * Reference implementation of the Developer Backend Integration Contract.
 *
 * This is NOT part of the Auth API. It shows what YOUR backend must implement.
 * Users are kept in memory here; replace the `db` object with your own database.
 *
 * Run:  INTEGRATION_SIGNING_SECRET=whsec_... node examples/developer-backend/server.mjs
 * Then provision your app with --backend-url https://<your-host>/auth-hook
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";

const SECRET = process.env.INTEGRATION_SIGNING_SECRET;
const PORT = Number(process.env.PORT ?? 4100);
if (!SECRET) throw new Error("INTEGRATION_SIGNING_SECRET is required");

// ---- Replace with your database ------------------------------------------
const usersByEmail = new Map();
let seq = 0;
const db = {
  findByEmail: async (email) => usersByEmail.get(email) ?? null,
  findById: async (id) => [...usersByEmail.values()].find((u) => u.user_id === id) ?? null,
  create: async (email, password_hash) => {
    const user = { user_id: `user_${++seq}`, email, password_hash, email_verified: false };
    usersByEmail.set(email, user);
    return user;
  },
};
// ---------------------------------------------------------------------------

/** Verify X-AuthAPI-Signature: v1=hex(HMAC_SHA256(secret, `${timestamp}.${rawBody}`)) */
function verifySignature(req, rawBody) {
  const timestamp = req.headers["x-authapi-timestamp"];
  const signature = String(req.headers["x-authapi-signature"] ?? "");
  if (!timestamp || Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false; // replay window
  const expected = "v1=" + createHmac("sha256", SECRET).update(`${timestamp}.${rawBody}`).digest("hex");
  return signature.length === expected.length && timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

function send(res, status, body) {
  if (body === undefined) return res.writeHead(status).end();
  res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
}

async function handleAuthHook(action, data) {
  switch (action) {
    case "user.create": {
      if (await db.findByEmail(data.email)) return [409, { error: "user_exists" }];
      const user = await db.create(data.email, data.password_hash); // store the Argon2id hash as-is
      return [201, { user_id: user.user_id, email: user.email }];
    }
    case "user.lookup": {
      const user = await db.findByEmail(data.email);
      if (!user) return [404, { error: "not_found" }];
      return [200, { user_id: user.user_id, email: user.email, password_hash: user.password_hash, email_verified: user.email_verified }];
    }
    case "user.get": {
      const user = await db.findById(data.user_id);
      if (!user) return [404, { error: "not_found" }];
      return [200, { user_id: user.user_id, email: user.email, email_verified: user.email_verified }];
    }
    // Only needed if you enable the optional email features:
    case "user.mark_email_verified": {
      const user = await db.findById(data.user_id);
      if (!user || user.email !== data.email) return [404, { error: "not_found" }];
      user.email_verified = true;
      return [204];
    }
    case "user.update_password": {
      const user = await db.findById(data.user_id);
      if (!user) return [404, { error: "not_found" }];
      user.password_hash = data.password_hash;
      return [204];
    }
    default:
      return [400, { error: "unknown_action" }];
  }
}

async function handleEmailHook(action, data) {
  if (action !== "email.send") return [400, { error: "unknown_action" }];
  // Send with Resend / SendGrid / SES ... Build the link in YOUR frontend, e.g.:
  const link =
    data.type === "email_verification"
      ? `https://app.example.com/verify-email?token=${encodeURIComponent(data.token)}`
      : `https://app.example.com/reset-password?token=${encodeURIComponent(data.token)}`;
  console.log(`[email] would send ${data.type} to ${data.to}: ${link.replace(data.token, "<token>")}`);
  return [202, { queued: true }];
}

createServer(async (req, res) => {
  if (req.method !== "POST") return send(res, 405, { error: "method_not_allowed" });
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 64 * 1024) return send(res, 413, { error: "too_large" });
  }
  if (!verifySignature(req, raw)) return send(res, 401, { error: "invalid_signature" });
  const { action, data } = JSON.parse(raw);
  const [status, body] =
    req.url === "/auth-hook" ? await handleAuthHook(action, data)
    : req.url === "/email-hook" ? await handleEmailHook(action, data)
    : [404, { error: "not_found" }];
  send(res, status, body);
}).listen(PORT, () => console.log(`Developer backend listening on :${PORT}`));
