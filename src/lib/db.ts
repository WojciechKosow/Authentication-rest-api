import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "@/generated/prisma/client";
import { getConfig } from "./config";

// Reuse a single client per process (and across hot reloads in development).
const globalForPrisma = globalThis as unknown as { __authApiPrisma?: PrismaClient };

export function getDb(): PrismaClient {
  if (!globalForPrisma.__authApiPrisma) {
    const adapter = new PrismaPg({ connectionString: getConfig().databaseUrl });
    globalForPrisma.__authApiPrisma = new PrismaClient({ adapter });
  }
  return globalForPrisma.__authApiPrisma;
}

export async function disconnectDb(): Promise<void> {
  if (globalForPrisma.__authApiPrisma) {
    await globalForPrisma.__authApiPrisma.$disconnect();
    globalForPrisma.__authApiPrisma = undefined;
  }
}
