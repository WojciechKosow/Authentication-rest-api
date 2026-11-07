import { authenticateApp } from "@/lib/apps";
import * as auth from "@/lib/auth-service";
import { ApiError } from "@/lib/errors";
import { getBearerToken, ok, preflight, route } from "@/lib/http";

export const GET = route(async (request) => {
  const app = await authenticateApp(request);
  const token = getBearerToken(request);
  if (!token) throw new ApiError("MISSING_ACCESS_TOKEN");
  return ok(await auth.me(app, token));
});

export const OPTIONS = preflight;
