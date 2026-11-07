import { authenticateApp } from "@/lib/apps";
import * as auth from "@/lib/auth-service";
import { getBearerToken, ok, preflight, readJson, route } from "@/lib/http";
import { logoutSchema } from "@/lib/validation";

export const POST = route(async (request) => {
  const app = await authenticateApp(request);
  const body = await readJson(request, logoutSchema);
  return ok(
    await auth.logout(app, {
      accessToken: getBearerToken(request),
      refreshToken: body.refresh_token,
      allSessions: body.all_sessions,
    }),
  );
});

export const OPTIONS = preflight;
