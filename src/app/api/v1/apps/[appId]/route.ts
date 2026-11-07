import * as dev from "@/lib/developer-service";
import { ok, preflight, readJson, route } from "@/lib/http";
import { appUpdateSchema } from "@/lib/validation";

export const GET = route(async (request, ctx) => {
  const developer = dev.authenticateDeveloper(request);
  return ok(await dev.getApp(developer, ctx.params.appId));
});

export const PATCH = route(async (request, ctx) => {
  const developer = dev.authenticateDeveloper(request);
  const body = await readJson(request, appUpdateSchema);
  return ok(await dev.updateApp(developer, ctx.params.appId, body));
});

export const DELETE = route(async (request, ctx) => {
  const developer = dev.authenticateDeveloper(request);
  return ok(await dev.deleteApp(developer, ctx.params.appId));
});

export const OPTIONS = preflight;
