<!-- bb04dc89-3f5a-4f21-bfc7-f177c14bc483 603bbd42-a787-4e50-b157-84828d951ad9 -->
# Implement Auth Architecture (Detailed)

This plan breaks down the implementation of the "Register User" feature into strictly ordered steps. Each step builds upon the previous ones, adhering to the Dependency Rule ("Dependencies only point inward").

## Phase 0: Tooling & Project Bootstrap

*Goal: Get a running Bun + Elysia + TS server with a "Hello World" endpoint.*
*Reasoning: Ensure the environment is correctly set up and the basic toolchain works before diving into complex architecture.*

1.  **Verify Bun Installation & Project Init**

    -   **Action**: Check `bun -v` and ensure `package.json` is set up.
    -   **Reasoning**: Confirm the runtime environment.

2.  **Create Basic Server Entry Point**

    -   **File**: `src/main.ts`
    -   **Reasoning**: A minimal entry point to start the server.

3.  **Implement Hello World Endpoint**

    -   **File**: `src/main.ts` (temporary)
    -   **Reasoning**: Verify the server can handle requests and return responses.

4.  **Run & Test Server**

    -   **Action**: Run `bun dev` (or `bun run src/main.ts`) and curl the endpoint.
    -   **Reasoning**: Confirm everything is working.

## Phase 1: The Foundation (Shared Kernel)

*Goal: Establish the core primitives that have ZERO dependencies.*
*Ref: [01-architecture.md#6-cross-cutting-concerns--shared-kernel](docs/01-architecture.md#6-cross-cutting-concerns--shared-kernel)*

5.  **Implement `Result` Pattern**

    -   **File**: `src/shared/kernel/types/Result.ts`
    -   **Reasoning**: Used by almost every function to handle errors type-safely without throwing exceptions.

6.  **Implement `AppError` Class**

    -   **File**: `src/shared/kernel/errors/AppError.ts`
    -   **Reasoning**: Standardizes error codes (Validation, Unauthorized, etc.) across the app.

7.  **Implement `Brand` Helper**

    -   **File**: `src/shared/kernel/types/Brand.ts`
    -   **Reasoning**: Required to create type-safe IDs (e.g., preventing passing a `TenantId` where a `UserId` is expected).

8.  **Define Common Types**

    -   **File**: `src/shared/kernel/types/index.ts`
    -   **Reasoning**: Defines `UserId`, `TenantId`, etc. using the Brand helper.

## Phase 2: Shared Infrastructure Capabilities

*Goal: Implement the tools our feature will need (Logging, IDs).*
*Ref: [01-architecture.md#6-cross-cutting-concerns--shared-kernel](docs/01-architecture.md#6-cross-cutting-concerns--shared-kernel)*

9.  **Install Dependencies**

    -   **Action**: `bun add @paralleldrive/cuid2`
    -   **Reasoning**: Required for the ID generator implementation.

10. **Implement `IIdGenerator` Interface**

    -   **File**: `src/shared/application/interfaces/IIdGenerator.ts`
    -   **Reasoning**: Defines the contract for generating IDs, allowing us to mock it in tests.

11. **Implement `Cuid2Generator` Adapter**

    -   **File**: `src/shared/infrastructure/ids/Cuid2Generator.ts`
    -   **Reasoning**: The concrete implementation of ID generation.

12. **Implement `ILogger` Interface**

    -   **File**: `src/shared/application/interfaces/ILogger.ts`
    -   **Reasoning**: Decouples the application from specific logging libraries.

13. **Implement `ConsoleLogger` Adapter**

    -   **File**: `src/shared/infrastructure/logging/ConsoleLogger.ts`
    -   **Reasoning**: A simple logger implementation for development.

14. **Setup Global Config**

    -   **File**: `src/shared/infrastructure/config/index.ts`
    -   **Reasoning**: Centralizes `process.env` access for type safety.

15. **Setup Database Connection**

    -   **File**: `src/shared/infrastructure/database/index.ts`
    -   **Reasoning**: Initializes the Drizzle client.

## Phase 3: Auth Feature - Domain Layer

*Goal: Define the business logic. Depends ONLY on Shared Kernel.*
*Ref: [01-architecture.md#layer-1-domain-domain](docs/01-architecture.md#layer-1-domain-domain)*

16. **Implement `Email` Value Object**

    -   **File**: `src/features/auth/domain/values/Email.ts`
    -   **Reasoning**: Encapsulates email validation rules so we don't repeat them.

17. **Implement `PasswordRules`**

    -   **File**: `src/features/auth/domain/rules/passwordRules.ts`
    -   **Reasoning**: Centralizes password complexity logic (min length, etc.).

18. **Implement `User` Entity**

    -   **File**: `src/features/auth/domain/entities/User.ts`
    -   **Reasoning**: The core business object. Defines behavior (create, restore) and holds state.

## Phase 4: Auth Feature - Application Layer

*Goal: Define the use case. Depends on Domain and Shared Application.*
*Ref: [01-architecture.md#layer-2-application--use-cases-application](docs/01-architecture.md#layer-2-application--use-cases-application)*

19. **Define Ports (Interfaces)**

    -   **Files**:
        -   `src/features/auth/application/ports/IUserRepository.ts`
        -   `src/features/auth/application/ports/IPasswordHasher.ts`
        -   `src/features/auth/application/ports/IEmailService.ts`
    -   **Reasoning**: Defines *what* the infrastructure needs to provide without defining *how*.

20. **Define Use Case DTOs**

    -   **File**: `src/features/auth/application/dtos/index.ts`
    -   **Reasoning**: Defines the input/output shapes for the Use Case, decoupling it from HTTP.

21. **Implement `RegisterUser` Use Case**

    -   **File**: `src/features/auth/application/usecases/RegisterUser.ts`
    -   **Reasoning**: Orchestrates the registration flow: Validate -> Hash -> Save -> Email.

## Phase 5: Auth Feature - Infrastructure Layer

*Goal: Implement the interfaces. Depends on Application, Domain, and Shared Infrastructure.*
*Ref: [01-architecture.md#layer-3-infrastructure-infrastructure](docs/01-architecture.md#layer-3-infrastructure-infrastructure)*

22. **Define Database Schema**

    -   **File**: `src/features/auth/infrastructure/schema/users.ts`
    -   **Reasoning**: Defines the PostgreSQL table structure for Drizzle.

23. **Implement Data Mapper**

    -   **File**: `src/features/auth/infrastructure/mappers/UserMapper.ts`
    -   **Reasoning**: Transforms DB rows into Domain Entities (using `User.restore`).

24. **Implement `BunPasswordHasher`**

    -   **File**: `src/features/auth/infrastructure/services/BunPasswordHasher.ts`
    -   **Reasoning**: Concrete implementation of password hashing using Bun's native crypto.

25. **Implement `DrizzleUserRepository`**

    -   **File**: `src/features/auth/infrastructure/repositories/DrizzleUserRepository.ts`
    -   **Reasoning**: Implements `IUserRepository` to save/load users from Postgres.

26. **Implement `EmailService` Stub**

    -   **File**: `src/features/auth/infrastructure/services/EmailService.ts`
    -   **Reasoning**: Concrete implementation of email sending (can be a log-only stub for now).

## Phase 6: Auth Feature - Presentation Layer

*Goal: Expose via HTTP. Depends on Application and Shared Presentation.*
*Ref: [01-architecture.md#layer-4-presentation-presentation](docs/01-architecture.md#layer-4-presentation-presentation)*

27. **Define Transport DTOs**

    -   **File**: `src/features/auth/presentation/http/dtos/RegisterRequestDto.ts`
    -   **Reasoning**: Defines the HTTP body schema (Elysia TypeBox) for validation.

28. **Implement Presentation Mappers**

    -   **File**: `src/features/auth/presentation/http/mappers/AuthMappers.ts`
    -   **Reasoning**: Maps HTTP DTOs -> Use Case DTOs and vice versa.

29. **Implement `authModule` (IOC)**

    -   **File**: `src/features/auth/ioc.ts`
    -   **Reasoning**: Wires up the dependencies (Repo, Hasher, Use Case) for this feature.

30. **Implement `AuthController`**

    -   **File**: `src/features/auth/presentation/http/AuthController.ts`
    -   **Reasoning**: Defines the routes, handles HTTP requests, and calls the Use Case.

## Phase 7: App Wiring

*Goal: Start the server.*
*Ref: [01-architecture.md#2-project-structure](docs/01-architecture.md#2-project-structure)*

31. **Wire App in `bootstrap/app.ts`**

    -   **File**: `src/bootstrap/app.ts`
    -   **Reasoning**: Composes the Elysia application with the Auth feature module.

32. **Start Server in `main.ts`**

    -   **File**: `src/main.ts`
    -   **Reasoning**: Entry point that runs the app.

### To-dos

- [ ] Implement Result Pattern
- [ ] Implement AppError Class
- [ ] Implement Brand Helper
- [ ] Define Common Types
- [ ] Install Dependencies
- [ ] Implement IIdGenerator Interface
- [ ] Implement Cuid2Generator Adapter
- [ ] Implement ILogger Interface
- [ ] Implement ConsoleLogger Adapter
- [ ] Setup Global Config
- [ ] Setup Database Connection
- [ ] Implement Email Value Object
- [ ] Implement PasswordRules
- [ ] Implement User Entity
- [ ] Define Ports (Interfaces)
- [ ] Define Use Case DTOs
- [ ] Implement RegisterUser Use Case
- [ ] Define Database Schema
- [ ] Implement Data Mapper
- [ ] Implement BunPasswordHasher
- [ ] Implement DrizzleUserRepository
- [ ] Implement EmailService Stub
- [ ] Define Transport DTOs
- [ ] Implement Presentation Mappers
- [ ] Implement authModule (IOC)
- [ ] Implement AuthController
- [ ] Wire App in bootstrap/app.ts
- [ ] Start Server in main.ts