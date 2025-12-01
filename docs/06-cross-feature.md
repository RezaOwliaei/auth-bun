
## 1. Cross-feature interfaces & communication

Think in terms of **features as mini bounded contexts**. Each feature exposes a small “public API” at the application layer, and other features talk to that API via ports or events, not by poking into its internals.

### 1.1 Principles

* **No direct domain-to-domain dependencies across features.**
  `auth/domain` should not import `users/domain`, etc.
* **Communication happens at the application layer**, via:

  * Synchronous calls: application ports / use cases
  * Asynchronous integration: domain/integration events
* **The consumer defines the port; the producer implements it.**
  This keeps dependency direction safe for Clean Architecture.

---

### 1.2 Synchronous cross-feature calls (ports)

Example: `tenants` needs to provision a user in `auth` when a tenant is created.

1. In the **consumer** (`tenants`) application layer, define a port:

```ts
// features/tenants/application/ports/IAuthUserProvisioningPort.ts
export interface IAuthUserProvisioningPort {
  provisionUser(input: {
    email: string;
    password: string;
    tenantId: TenantId;
  }): Promise<{ userId: UserId }>;
}
```

2. The tenant use-case depends on that port:

```ts
// features/tenants/application/usecases/CreateTenant.ts
export class CreateTenant {
  constructor(
    private readonly authProvisioning: IAuthUserProvisioningPort,
    // ...other ports
  ) {}

  async execute(input: CreateTenantInput): Promise<CreateTenantOutput> {
    const tenant = /* create tenant aggregate */;
    const { userId } = await this.authProvisioning.provisionUser({
      email: input.ownerEmail,
      password: input.ownerPassword,
      tenantId: tenant.id,
    });

    // persist tenant + owner ref, etc.
  }
}
```

3. In the **producer** feature (`auth`), implement that port using its own use cases:

```ts
// features/auth/application/adapters/AuthUserProvisioningAdapter.ts
import { IAuthUserProvisioningPort } from "../../tenants/application/ports/IAuthUserProvisioningPort"; // or better: re-export from a central place

export class AuthUserProvisioningAdapter implements IAuthUserProvisioningPort {
  constructor(private readonly registerUser: RegisterUser) {}

  async provisionUser(input: {
    email: string;
    password: string;
    tenantId: TenantId;
  }): Promise<{ userId: UserId }> {
    const result = await this.registerUser.execute({
      email: input.email,
      password: input.password,
      tenantId: input.tenantId,
    });

    if (result.isFailure) {
      throw result.error; // or map to AppError
    }

    return { userId: result.value.userId };
  }
}
```

4. **Wire it in the composition root** (`bootstrap/app.ts` or `features/*/ioc.ts`):

```ts
const authFeature = createAuthFeature({ /* db, logger, etc. */ });

const tenantsFeature = createTenantsFeature({
  authUserProvisioningPort: new AuthUserProvisioningAdapter(
    authFeature.useCases.registerUser
  ),
});
```

Key points:

* `tenants` knows only `IAuthUserProvisioningPort`.
* Implementation can live in `auth` (since it knows its own use cases), or in a small cross-feature `integration` spot.
* Dependency direction: `tenants` → its own port interface, not directly to `auth`. The adapter depends on `auth` but that’s wired in the IoC, not in the domain/application.

---

### 1.3 Asynchronous / event-based communication

Some interactions are better via events (e.g. audit logs, welcome emails, projections):

* **Domain events** stay inside the feature (`auth/domain/events/UserRegisteredEvent.ts`).
* **Integration events** are the cross-feature contract.

Pattern:

1. In `auth/domain/events` you already have `UserRegisteredEvent.ts`. Keep that as a pure domain event.

2. In the `auth/application` layer, translate that to an **integration event** and publish via an `IEventBus`:

```ts
// common/core/events/IEventBus.ts
export interface IEventBus {
  publish(event: IntegrationEvent): Promise<void>;
}
```

```ts
// features/auth/application/subscribers/UserRegisteredIntegrationPublisher.ts
export class UserRegisteredIntegrationPublisher {
  constructor(private readonly eventBus: IEventBus) {}

  async handle(event: UserRegisteredEvent): Promise<void> {
    await this.eventBus.publish({
      type: "auth.user.registered",
      payload: {
        userId: event.userId,
        email: event.email,
        occurredAt: event.occurredAt,
      },
    });
  }
}
```

3. In another feature (`tenants`, `users`, `analytics`), subscribe via application-layer handlers:

```ts
// features/tenants/application/subscribers/OnUserRegistered.ts
export class OnUserRegistered {
  constructor(private readonly repo: ITenantRepository) {}

  async handle(event: AuthUserRegisteredIntegrationEvent) {
    // react: e.g., attach user to default tenant, send internal notification, etc.
  }
}
```

Inside a single process, the “event bus” can be an in-memory implementation. Later you can swap to Kafka/SQS, etc., via infrastructure.

---

### 1.4 “Public API” for each feature

To make cross-feature usage explicit, consider giving each feature a small public surface:

```ts
// features/auth/public.ts
export type AuthUseCases = {
  registerUser: RegisterUser;
  loginUser: LoginUser;
  // ...
};

export function createAuthFeature(deps: AuthDependencies): AuthUseCases {
  // wire domain/application/infra, return only what other features should use
}
```

Then composition root passes only those public use cases into other features’ adapters. That prevents random imports from `features/auth/**` all over the place.

---

## 2. Should we introduce a Shared Kernel directory?

Short answer: **yes, but keep it very small and very intentional.**

Right now you have:

* `common/error/Result.ts`, `AppError.ts`
* `common/types/Brand.ts`, `PrimitiveTypes.ts`
* Some things that will likely become **shared domain concepts** soon (IDs, maybe Email, TenantId, etc.)

It’s useful to separate:

1. **Shared technical concerns** (logging, config, DB, framework/bus utilities)
2. **Shared domain kernel** (value objects / types that truly belong to more than one feature)

I’d introduce:

```text
src/
  shared-kernel/
    domain/
      errors/
        AppError.ts        # domain-safe error type or base
      result/
        Result.ts
      types/
        Brand.ts
        PrimitiveTypes.ts
      ids/
        UserId.ts
        TenantId.ts
      value-objects/
        EmailAddress.ts    # if truly shared beyond auth
    application/
      # If you have app-level specific variants of Result/AppError, or common DTO primitives
```

Guidelines for what goes into `shared-kernel`:

* **Pure, framework-agnostic, domain-safe.**
* Used by **multiple features’ domain/application layers**.
* Concepts that are **stable** (not changing every sprint).
* No Drizzle, Bun, Elysia, JWT libs, etc.

Things that should **not** go into `shared-kernel`:

* Concrete repositories, schemas, external service clients
* HTTP middlewares, controllers, route handlers
* Anything that directly uses infrastructure libraries

If only `auth` cares about a value object (e.g. `Password` hash/rules), it stays in `features/auth/domain/values`.
If multiple features share email semantics and invariants, it can be promoted to `shared-kernel/domain/value-objects/EmailAddress.ts`.

---

## 3. How to break down `src/common`

Right now `common` mixes:

* Technical cross-cutting (config, db, logger, id generator, middleware)
* Core/domain-safe primitives (Result, AppError, Brand, PrimitiveTypes)
* Presentation-specific bits (`middleware/authMiddleware.ts`, `errorHandler.ts`, `logger.ts` which are Elysia/Bun HTTP middleware)

From a Clean Architecture perspective, you want to **separate by layer and by concern**.

### 3.1 A concrete refactor suggestion

I’d split `common` into two (or three) top-level modules:

```text
src/
  shared-kernel/          # shared domain & app primitives (see above)
  platform/               # cross-cutting infra & presentation utilities
  features/
  bootstrap/
```

Then map your current `common` into that:

```text
src/
  shared-kernel/
    domain/
      errors/
        AppError.ts
      result/
        Result.ts
    types/
      Brand.ts
      PrimitiveTypes.ts

  platform/
    config/
      index.ts             # env, app-level config
    db/
      index.ts             # Drizzle/Bun DB instance
      migrate.ts           # migration runner
    logging/
      ILogger.ts           # interface can be here OR in shared-kernel if used by domain
      ConsoleLogger.ts
    id/
      IIdGenerator.ts      # can be interface-only here, used by app/domain
      Cuid2Generator.ts
    http/
      middleware/
        errorHandler.ts    # Elysia HTTP middleware
        logger.ts
        authMiddleware.ts  # JWT/session/RBAC (presentation-level)
```

Key clean-architecture boundaries:

* `shared-kernel` can be safely imported by **domain/application** code.
* `platform` should **not** be imported by domain. Application can depend on abstractions (`ILogger`, `IIdGenerator`, `IEventBus`) but their concrete implementations (ConsoleLogger, Cuid2Generator, InMemoryEventBus) live in `platform` or each feature’s `infrastructure`.
* Presentation-specific things (HTTP middleware, controllers, DTO mappers) should be under **presentation**, even if cross-feature:

  ```text
  src/
    presentation/
      http/
        middleware/
          authMiddleware.ts
          errorHandler.ts
          logger.ts
  ```

  Then each feature’s own presentation stays under `features/<feature>/presentation/http/...`.

If you want to keep the `common` folder name, you can still **mirror the layering inside it**:

```text
src/common/
  core/                    # domain-safe primitives
    error/
      Result.ts
      AppError.ts
    types/
      Brand.ts
      PrimitiveTypes.ts
    ports/
      ILogger.ts
      IIdGenerator.ts
      IEventBus.ts
  infrastructure/
    db/
      index.ts
      migrate.ts
    logging/
      ConsoleLogger.ts
    id/
      Cuid2Generator.ts
  presentation/
    http/
      middleware/
        authMiddleware.ts
        errorHandler.ts
        logger.ts
```

The important bit is not the exact names, but:

* **Interfaces vs implementations** are separated.
* **Domain-safe vs infra/presentation-specific** are separated.
* Features import only what their layer is allowed to see.

---

### 3.2 Where should JWT verification / session / RBAC live?

To tie this back to your earlier question:

* **JWT verification & session extraction**: HTTP middleware in `presentation/http/middleware/authMiddleware.ts`.

* That middleware should:

  * Verify tokens, parse claims.
  * Build an `AuthenticatedUser` / `RequestContext` object.
  * Attach it to the request (e.g. `ctx.auth`).

* **Authorization decisions (RBAC checks)**:

  * Simple route-level guards (e.g. “must be logged in”) can still live in presentation.
  * More complex business-level checks (“only tenant owner can invite users”, “only superadmin can create tenants”) belong **inside use cases**, expressed in domain terms. For that, you pass the `AuthenticatedUser` (or a narrower `Caller` context) from presentation into the use case.

The types for `AuthenticatedUser`, `Role`, `Permission` enums can live either in:

* `shared-kernel` (if widely shared), or
* `features/auth/domain` (if strongly owned by auth).

---

## Summary

1. **Cross-feature communication**

   * Use application-layer ports (consumer defines, producer implements) and/or integration events.
   * Each feature exposes a small “public API” from its application layer.

2. **Shared Kernel**

   * Yes, but keep it tiny and domain-focused: Result, AppError, brand/ID types, truly shared value objects.
   * No infrastructure or framework-specific code there.

3. **Breaking down `src/common`**

   * Split into domain-safe core (`shared-kernel` / `core`) vs platform/infra/presentation utilities (`platform` / `infrastructure` / `presentation`).
   * Separate interfaces from implementations, and keep HTTP middleware clearly in the presentation layer.

If you want, next step we can take your actual `common/*` files and draft a concrete before/after tree plus a couple of updated import paths so you can refactor with minimal friction.
