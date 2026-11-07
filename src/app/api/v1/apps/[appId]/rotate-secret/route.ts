import * as dev from "@/lib/developer-service";
import { ok, preflight, route } from "@/lib/http";

export const POST = route(async (request, ctx) => {
  const developer = dev.authenticateDeveloper(request);
  return ok(await dev.rotateAppSecret(developer, ctx.params.appId));
});

export const OPTIONS = preflight;
