import { defineConfig } from "prisma/config";

// DATABASE_URL is provided by the environment (Railway injects it from the
// PostgreSQL service; locally export it or use `node --env-file`).
// `prisma generate` does not need a database, so an empty fallback is fine.
export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
  },
  datasource: {
    url: process.env.DATABASE_URL ?? "",
  },
});
