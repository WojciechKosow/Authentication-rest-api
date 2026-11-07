import { authenticateApp } from "@/lib/apps";
import * as auth from "@/lib/auth-service";
import { ok, preflight, readJson, route } from "@/lib/http";
import { registerSchema } from "@/lib/validation";

export const POST = route(async (request, ctx) => {
  const app = await authenticateApp(request);
  const body = await readJson(request, registerSchema);
  return ok(await auth.register(app, ctx.clientIp, body.email, body.password), 201);
});

export const OPTIONS = preflight;
