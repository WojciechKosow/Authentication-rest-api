import { authenticateApp } from "@/lib/apps";
import * as auth from "@/lib/auth-service";
import { ok, preflight, readJson, route } from "@/lib/http";
import { verifyEmailConfirmSchema } from "@/lib/validation";

export const POST = route(async (request, ctx) => {
  const app = await authenticateApp(request);
  const body = await readJson(request, verifyEmailConfirmSchema);
  return ok(await auth.confirmEmailVerification(app, ctx.clientIp, body.token));
});

export const OPTIONS = preflight;
