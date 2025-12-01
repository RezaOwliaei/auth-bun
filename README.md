# Auth Bun

````markdown
# Auth Bun

## Project Definition

Bun implementation of [FusionAuth](https://fusionauth.io) for learning purposes.

## Architecture

- Feature-first Clean Architecture

## Stack

- **Runtime**: Bun
- **Database**: Postgres
- **Containerization**: Docker

## Getting Started

First, copy `.env.example` to `.env.local` and fill in the database credentials (use `POSTGRES_HOST=db` when running inside Docker Compose). `.env.local` is highest priority for Bun and Compose (dev only; staging/prod use `.env.production`).

Run database migrations for your target environment (creates/updates schema):

```bash
bun run migrate:dev      # or migrate:staging / migrate:prod
```

Then start the development environment (with hot-reloading):

```bash
bun run dev
```

The application will be available at `http://localhost:3000`.

To run the end-to-end tests:

```bash
bun run test:e2e
```

## Environment Setup

- **Copy env files**: Duplicate `.env.example` for each environment and fill values:

  - Local overrides: `.env.local`
  - Development: `.env.development`
  - Production/Staging: `.env.production` (do not use `.env.local` on servers)
  - Tests: `.env.test`

- **Recommended variables** (project may accept either a single `DATABASE_URL` or classic PG vars):

  - `NODE_ENV` — `development|staging|production`
  - `APP_PORT` — typically `3000`
  - `POSTGRES_HOST` — `db` when using Docker Compose
  - `POSTGRES_PORT` — `5432` (container port)
  - `DB_PORT` — host-mapped port (e.g., `5433` locally)
  - `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`
  - Optional: `DATABASE_URL` — falls back to the above PG vars

- **Secrets**: Do not commit `.env.production` to source control. Use your platform's secret store (Kubernetes secrets, Docker secrets, cloud environment variables, or HashiCorp Vault) for production credentials.
- **Bun env loading**: Bun auto-loads `.env`, `.env.local`, and `.env.<NODE_ENV>` (e.g., `.env.development`). For the provided `.env.local/.env.development/.env.production/.env.test` files, pass `--env-file` when running Bun commands locally. Staging/production should only reference `.env.production`.

## Running: Development, Staging, Production

- The project provides npm scripts which wrap Docker Compose. Use the script matching the target environment:

```bash
# Development (interactive, with logs):
bun run dev

# Start staging (detached):
bun run staging

# Start production (detached):
bun run prod

# Stop all services started by compose:
bun run down:dev
bun run down:staging
bun run down:prod
```

- These scripts reference the following compose files in the repository:

  - `docker-compose.yml` — base configuration
  - `docker-compose.dev.yml` — development overrides (hot reload, mounts)
  - `docker-compose.staging.yml` — staging overrides
  - `docker-compose.prod.yml` — production overrides
  - `docker-compose.test.yml` — test/e2e configuration

- If you prefer Docker Compose directly, the equivalent commands are (note the env files and project names to isolate containers/volumes per environment):

```bash
docker-compose --env-file .env.local --env-file .env.development -p auth-bun-dev -f docker-compose.yml -f docker-compose.dev.yml up --build
docker-compose --env-file .env.production -p auth-bun-staging -f docker-compose.yml -f docker-compose.staging.yml up --build -d
docker-compose --env-file .env.production -p auth-bun-prod -f docker-compose.yml -f docker-compose.prod.yml up --build -d
```

## Database migrations (Drizzle)

- Config lives in `drizzle.config.ts`.
  - Feature schemas: `src/features/*/infrastructure/schema/*.ts`
  - Common schema: `src/common/db/schema.ts` (for shared enums, relations, or tables not specific to a single feature)
  - Output: `./drizzle`
- Generate SQL migrations from schema changes:

```bash
bun run db:generate
```

- Apply migrations locally (outside Docker) using your active env file:

```bash
bun --env-file .env.local --env-file .env.development run db:migrate
```

- Apply migrations with Docker Compose (recommended for staging/prod so the same image/env are used):

```bash
bun run migrate:staging   # or migrate:prod / migrate:dev / migrate:test
```

- `bun run test:e2e` automatically runs migrations for the test stack before executing tests.

- Optional migration service: the compose stack includes a `migrate` service behind the `migrations` profile. Include `--profile migrations` in your compose command if you want migrations to run as part of `up`; otherwise run the `migrate:<env>` scripts before bringing up app containers.

## Environment guides

### Local development
- Env files: `.env.local` (overrides) + `.env.development`.
- Start stack with hot reload:
  ```bash
  bun run dev
  ```
- Run migrations:
  ```bash
  bun run migrate:dev          # compose-based
  # or outside compose:
  bun --env-file .env.local --env-file .env.development run db:migrate
  ```
- Stop:
  ```bash
  bun run down:dev
  ```
- Notes: Postgres exposed on `DB_PORT` (default 5433). App healthcheck expects `/health`.

### Test / CI
- Env file: `.env.test` (no `.env.local`).
- Run migrations and tests:
  ```bash
  bun run migrate:test
  bun run test:e2e
  ```
- CI outline:
  1) Provide `.env.test` via secrets.
  2) `bun install --frozen-lockfile`
  3) `bun run migrate:test`
  4) `bun run test:e2e`
  5) Optionally build image for cache/validation: `docker-compose -f docker-compose.yml -f docker-compose.prod.yml build`

### Staging
- Env file: `.env.production` (staging values). Keep `.env.local` off servers.
- Run migrations, then bring up stack:
  ```bash
  bun run migrate:staging                # one-off migrations
  bun run staging                        # detached
  # or include migrations profile to run migrations during up:
  NODE_ENV=production docker-compose --env-file .env.production --profile migrations -p auth-bun-staging -f docker-compose.yml -f docker-compose.staging.yml up --build -d
  ```
- Healthchecks: Postgres via `pg_isready`, app via `/health`.

### Production
- Env file: `.env.production` (prod values only; managed via secret store).
- Run migrations, then bring up stack:
  ```bash
  bun run migrate:prod
  bun run prod
  # or with migrations profile:
  NODE_ENV=production docker-compose --env-file .env.production --profile migrations -p auth-bun-prod -f docker-compose.yml -f docker-compose.prod.yml up --build -d
  ```
- Recommended: build images in CI, push to registry, and deploy with compose referencing the image tag instead of building on host.

### General best practices
- Keep `.env.local` off servers; only `.env.production` should exist on staging/prod hosts.
- Ensure `/health` endpoint is implemented to satisfy the app healthcheck.
- Pin dependency versions before releasing to staging/prod.
- When running compose manually, add `--profile migrations` if you want migrations to run automatically; otherwise run the `migrate:<env>` scripts before `up`.

## Deploy Notes

- The `staging` and `prod` compose files are intended to be used on servers or CI runners where the appropriate environment variables are provided.
- Ensure your Postgres instance is reachable from the deployed hosts and `DATABASE_URL` (or PG vars) are set to point to the correct DB.
- Docker Compose will build images as part of the `--build` step; in production you may prefer to build images in CI and deploy images from a registry instead of building on the target host.

## Troubleshooting

- If the server is unreachable, confirm `PORT` and that the Docker container is healthy: `docker ps` + `docker logs <container>`.
- Database connection errors usually indicate a missing or incorrect `DATABASE_URL` or network access problems to the database host.
- If ports collide locally, change `PORT` in `.env.development` or stop the occupying service.

## Further Reading

- See `docs/01-architecture.md` and `docs/02-features.md` for project architecture and feature descriptions.
````
