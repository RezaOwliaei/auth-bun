# Project Implementation Plan

A step-by-step guide to building the application.

## Phase 1: Project Setup & Foundation
**Goal**: Get the environment running and database connected.

1.  **Environment Setup**:
    -   [x] Initialize Bun project (`bun init`).
    -   [x] Setup Docker Compose for Postgres.
    -   [ ] Create `.env` file for secrets (DB URL, JWT Secret).
    -   [ ] Create `src/ioc.ts` for the Composition Root (Dependency Injection setup).
2.  **Database Setup**:
    -   [ ] Configure Drizzle ORM (`src/common/db/index.ts`).
    -   [ ] Create a "Health Check" API route in Elysia to verify DB connection.
    -   [ ] Run `bun run dev` and verify everything works.

## Phase 2: The Tenant Feature (The Container)
**Goal**: Implement the multi-tenancy foundation.

1.  **Domain**:
    -   Define `Tenant` entity (id, name, created_at).
    -   Define `ITenantRepository` interface.
2.  **Data**:
    -   Create Drizzle schema `tenants` in `src/features/tenants/data/schema.ts`.
    -   Implement `DrizzleTenantRepository`.
    -   Run migration: `bun x drizzle-kit generate` & `migrate`.
3.  **Core**:
    -   Create `CreateTenant` use case.
    -   Create `GetTenant` use case.
4.  **API**:
    -   Create POST `/api/tenants` endpoint.
    -   Create GET `/api/tenants/:id` endpoint.

## Phase 3: User Registration (The Core)
**Goal**: Allow users to sign up.

1.  **Domain**:
    -   Define `User` entity.
    -   Define `IUserRepository`.
2.  **Data**:
    -   Create `users` schema (email, password_hash, tenant_id).
    -   Implement repository.
3.  **Core**:
    -   **Password Hashing**: Create a `PasswordService` (using `bun:password` or `argon2`).
    -   **RegisterUser Use Case**:
        -   Check if email exists in Tenant.
        -   Hash password.
        -   Save user.
4.  **API**:
    -   POST `/api/auth/register`.

## Phase 4: Authentication (Login & JWT)
**Goal**: Issue tokens for valid credentials.

1.  **Token Service**:
    -   Implement `JwtService` using `@elysiajs/jwt` or `jose`.
    -   Functions to `sign` and `verify` tokens.
2.  **Login Use Case**:
    -   Input: Email, Password, TenantId.
    -   Verify password.
    -   Generate JWT (Access Token).
    -   Return tokens.
3.  **API**:
    -   POST `/api/auth/login`.

## Phase 5: Middleware & Protection
**Goal**: Protect routes.

1.  **Auth Middleware**:
    -   Create an Elysia plugin/middleware.
    -   Extract `Authorization: Bearer <token>`.
    -   Verify token.
    -   Attach `user` and `tenant` to the request context.
2.  **Test**:
    -   Create a protected route `GET /api/users/me`.
    -   Verify it fails without token and succeeds with one.

## Phase 6: Refresh Tokens (Long-lived sessions)
**Goal**: Securely maintain sessions.

1.  **Schema**: Add `refresh_tokens` table.
2.  **Login Update**: Generate and save Refresh Token alongside Access Token.
3.  **Refresh Endpoint**:
    -   POST `/api/auth/refresh`.
    -   Validate refresh token -> Issue new Access Token.

## Phase 7: Polish & Refactor
1.  **Validation**: Add input validation (Zod/TypeBox) to all Controllers.
2.  **Error Handling**: Global error handler for consistent JSON responses.
3.  **Logging**: Add structured logging.
