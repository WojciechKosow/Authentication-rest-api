import { authenticateApp } from "@/lib/apps";
import * as auth from "@/lib/auth-service";
import { ok, preflight, readJson, route } from "@/lib/http";
import { validateSchema } from "@/lib/validation";

export const POST = route(async (request) => {
  const app = await authenticateApp(request);
  const body = await readJson(request, validateSchema);
  return ok(await auth.validate(app, body.access_token));
});

export const OPTIONS = preflight;
