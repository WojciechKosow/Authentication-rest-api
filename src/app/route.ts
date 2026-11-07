import { ok, route } from "@/lib/http";

export const GET = route(
  async () =>
    ok({
      name: "Authentication API",
      version: "v1",
      health: "/api/v1/health",
      endpoints: [
        "POST /api/v1/auth/register",
        "POST /api/v1/auth/login",
        "POST /api/v1/auth/refresh",
        "POST /api/v1/auth/logout",
        "GET /api/v1/auth/me",
        "POST /api/v1/auth/validate",
        "POST /api/v1/auth/email/verify/request",
        "POST /api/v1/auth/email/verify/confirm",
        "POST /api/v1/auth/password/reset/request",
        "POST /api/v1/auth/password/reset/confirm",
        "POST /api/v1/apps",
        "GET /api/v1/apps",
        "GET|PATCH|DELETE /api/v1/apps/{app_id}",
        "POST /api/v1/apps/{app_id}/rotate-secret",
        "POST /api/v1/apps/{app_id}/rotate-integration-secret",
        "POST /api/v1/apps/{app_id}/test-backend",
      ],
      getting_started: "Create your application with POST /api/v1/apps through RapidAPI.",
    }),
  { gateway: false },
);
