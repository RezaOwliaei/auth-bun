import { env } from "bun";
import { defineConfig } from "drizzle-kit";

const databaseUrl =
  env.DATABASE_URL ??
  `postgres://${env.POSTGRES_USER ?? "postgres"}:${env.POSTGRES_PASSWORD ?? "password"}@${
    env.POSTGRES_HOST ?? "localhost"
  }:${env.POSTGRES_PORT ?? "5432"}/${env.POSTGRES_DB ?? "postgres"}`;

export default defineConfig({
  schema: ["./src/common/db/schema.ts", "./src/features/*/infrastructure/schema/*.ts"],
  out: "./drizzle",
  dialect: "postgresql",
  dbCredentials: { url: databaseUrl },
  strict: true,
});
