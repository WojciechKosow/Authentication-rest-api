import { authenticateApp } from "@/lib/apps";
import * as auth from "@/lib/auth-service";
import { ok, preflight, readJson, route } from "@/lib/http";
import { loginSchema } from "@/lib/validation";

export const POST = route(async (request, ctx) => {
  const app = await authenticateApp(request);
  const body = await readJson(request, loginSchema);
  return ok(await auth.login(app, ctx.clientIp, body.email, body.password));
});

export const OPTIONS = preflight;
