// Shared test environment (never used outside tests).
export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? "postgresql://postgres@127.0.0.1:5432/authapi_test";

export const TEST_ENV: Record<string, string> = {
  NODE_ENV: "test",
  DATABASE_URL: TEST_DATABASE_URL,
  JWT_MASTER_SECRET: "test-jwt-master-7f3a9c1e5b2d8f4a6c0e9b1d3f5a7c9e",
  INTEGRATION_MASTER_SECRET: "test-integration-master-2b4d6f8a0c1e3a5c7e9b0d2f4a6c8e1b",
  JWT_ISSUER: "https://auth.test.local",
  INTEGRATION_ALLOW_PRIVATE_URLS: "true",
  INTEGRATION_TIMEOUT_MS: "1000",
  LOG_LEVEL: "silent",
};
