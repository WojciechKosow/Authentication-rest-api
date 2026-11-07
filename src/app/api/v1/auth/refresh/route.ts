import { authenticateApp } from "@/lib/apps";
import * as auth from "@/lib/auth-service";
import { ok, preflight, readJson, route } from "@/lib/http";
import { refreshSchema } from "@/lib/validation";

export const POST = route(async (request, ctx) => {
  const app = await authenticateApp(request);
  const body = await readJson(request, refreshSchema);
  return ok(await auth.refresh(app, ctx.clientIp, body.refresh_token));
});

export const OPTIONS = preflight;
