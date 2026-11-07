import { authenticateApp } from "@/lib/apps";
import * as auth from "@/lib/auth-service";
import { ok, preflight, readJson, route } from "@/lib/http";
import { passwordResetConfirmSchema } from "@/lib/validation";

export const POST = route(async (request, ctx) => {
  const app = await authenticateApp(request);
  const body = await readJson(request, passwordResetConfirmSchema);
  return ok(await auth.confirmPasswordReset(app, ctx.clientIp, body.token, body.new_password));
});

export const OPTIONS = preflight;
