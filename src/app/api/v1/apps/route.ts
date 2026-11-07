import * as dev from "@/lib/developer-service";
import { ok, preflight, readJson, route } from "@/lib/http";
import { appCreateSchema } from "@/lib/validation";

/** Self-service: list the caller's applications (RapidAPI user). */
export const GET = route(async (request) => {
  const developer = dev.authenticateDeveloper(request);
  return ok(await dev.listApps(developer));
});

/** Self-service: create an application bound to the caller's RapidAPI user. */
export const POST = route(async (request) => {
  const developer = dev.authenticateDeveloper(request);
  const body = await readJson(request, appCreateSchema);
  return ok(await dev.createApp(developer, body), 201);
});

export const OPTIONS = preflight;
