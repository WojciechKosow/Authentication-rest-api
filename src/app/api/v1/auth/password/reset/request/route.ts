import { authenticateApp } from "@/lib/apps";
import * as auth from "@/lib/auth-service";
import { ok, preflight, readJson, route } from "@/lib/http";
import { emailRequestSchema } from "@/lib/validation";

export const POST = route(async (request, ctx) => {
  const app = await authenticateApp(request);
  const body = await readJson(request, emailRequestSchema);
  return ok(await auth.requestPasswordReset(app, ctx.clientIp, body.email), 202);
});

export const OPTIONS = preflight;
