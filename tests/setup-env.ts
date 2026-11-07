import { TEST_ENV } from "./test-env";

for (const [k, v] of Object.entries(TEST_ENV)) process.env[k] = v;
delete process.env.REDIS_URL;
delete process.env.RAPIDAPI_PROXY_SECRET;
delete process.env.CORS_ALLOWED_ORIGINS;
