import { execSync } from "node:child_process";
import { TEST_DATABASE_URL } from "./test-env";

export default function setup() {
  // Apply pending migrations to the dedicated test database (tables are truncated per test).
  execSync("npx prisma migrate deploy", {
    stdio: "pipe",
    env: { ...process.env, DATABASE_URL: TEST_DATABASE_URL },
  });
}
