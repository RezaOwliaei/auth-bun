# Error Handling & The Result Pattern

This document explains how we handle errors in this application using the Result pattern, a type-safe alternative to throwing exceptions.

---

## Table of Contents

1. [The Problem with Traditional Error Handling](#1-the-problem-with-traditional-error-handling)
2. [Understanding the Result Pattern](#2-understanding-the-result-pattern)
3. [Result Pattern in Clean Architecture](#3-result-pattern-in-clean-architecture)
4. [Implementation Guide](#4-implementation-guide)
5. [Usage in Different Layers](#5-usage-in-different-layers)
6. [Best Practices for Bun/Elysia Projects](#6-best-practices-for-bunelysia-projects)
7. [Common Patterns & Recipes](#7-common-patterns--recipes)
8. [Testing with Result Pattern](#8-testing-with-result-pattern)

---

## 1. The Problem with Traditional Error Handling

### The Exception-Based Approach

Most TypeScript applications handle errors by throwing exceptions:

```typescript
// ❌ Traditional approach with exceptions
async function registerUser(email: string, password: string): Promise<User> {
  if (!email) {
    throw new Error("Email is required");
  }
  
  if (password.length < 8) {
    throw new ValidationError("Password must be at least 8 characters");
  }
  
  const existingUser = await userRepository.findByEmail(email);
  if (existingUser) {
    throw new ConflictError("User already exists");
  }
  
  return await userRepository.create({ email, password });
}

// Usage
try {
  const user = await registerUser(email, password);
  console.log("Success:", user);
} catch (error) {
  // What kind of error is this?
  // Is it validation? Conflict? Network? Unknown?
  console.error("Failed:", error);
}
```

### Why This Is Problematic

| Problem | Description | Impact |
|---------|-------------|--------|
| **Invisible Errors** | Function signature doesn't indicate it can fail | Callers forget to handle errors |
| **Type Ambiguity** | `catch (error)` has type `unknown` | Need runtime checks to understand error type |
| **Control Flow** | Exceptions interrupt normal flow | Hard to follow, unexpected jumps |
| **No Compiler Help** | TypeScript can't enforce error handling | Runtime errors slip through |
| **Testing Difficulty** | Need try-catch in every test | Verbose, error-prone test code |
| **Business vs System Errors** | Both use the same mechanism | Can't distinguish expected from unexpected failures |

### The Hidden Contract Problem

```typescript
// What errors can this throw?
// - ValidationError?
// - NotFoundError?
// - DatabaseError?
// - NetworkError?
// 
// The signature doesn't tell us!
async function loginUser(email: string, password: string): Promise<LoginResult> {
  // Implementation hidden
}
```

**The problem**: The function signature is a **lie**. It promises to return `LoginResult`, but it can also throw any number of errors. This is an invisible contract.

### Real-World Example: The Registration Flow

```typescript
// ❌ Exception-based (unclear what can fail)
async function handleRegistration(req: Request) {
  try {
    const user = await registerUser(req.body.email, req.body.password);
    return { status: 201, data: user };
  } catch (error) {
    // Runtime type checking (gross!)
    if (error instanceof ValidationError) {
      return { status: 400, message: error.message };
    }
    if (error instanceof ConflictError) {
      return { status: 409, message: error.message };
    }
    // What else could be thrown? We don't know!
    return { status: 500, message: "Something went wrong" };
  }
}
```

**Problems**:
1. No way to know all possible error types without reading implementation
2. Easy to forget handling a specific error type
3. TypeScript doesn't help us
4. Runtime type checks are ugly and error-prone

---

## 2. Understanding the Result Pattern

### The Core Concept

Instead of throwing exceptions, **return a Result object** that explicitly represents success or failure.

```typescript
// A Result is either:
// - Ok<T>: Success with value of type T
// - Err<E>: Failure with error of type E
type Result<T, E> = Ok<T> | Err<E>;
```

### Visual Representation

```
┌─────────────────────────────────────────┐
│            Result<User, Error>          │
├─────────────────────────────────────────┤
│                                         │
│  ┌────────────┐      ┌───────────────┐ │
│  │ Ok(user)   │  OR  │ Err(error)    │ │
│  │            │      │               │ │
│  │ isOk = true│      │ isOk = false  │ │
│  │ value: User│      │ error: Error  │ │
│  └────────────┘      └───────────────┘ │
│                                         │
└─────────────────────────────────────────┘
```

### Simple Example

```typescript
// ✅ Result-based approach
function divide(a: number, b: number): Result<number, string> {
  if (b === 0) {
    return err("Cannot divide by zero");
  }
  return ok(a / b);
}

// Usage
const result = divide(10, 2);

if (result.isOk) {
  console.log("Result:", result.value);  // TypeScript knows value exists
} else {
  console.log("Error:", result.error);   // TypeScript knows error exists
}
```

### Why This Is Better

| Benefit | Description | Example |
|---------|-------------|---------|
| **Explicit Failures** | Function signature shows it can fail | `Result<User, UserError>` |
| **Type Safety** | Compiler forces you to check for errors | TypeScript error if you forget `if (result.isOk)` |
| **No Surprises** | All failure modes are documented in types | Can't miss an error type |
| **Testability** | Easy to test both success and failure | No try-catch needed |
| **Composability** | Chain operations naturally | `result.map().andThen()` |
| **Clear Intent** | Business errors vs system errors | Different return types |

---

## 3. Result Pattern in Clean Architecture

### Where to Use Result Pattern

The Result pattern shines in **business logic layers** where failures are **expected and recoverable**.

```
┌────────────────────────────────────────────┐
│  API Layer                                 │
│  - Convert Results to HTTP responses       │
│  - Use Result pattern for consistency      │
└──────────────────┬─────────────────────────┘
                   ↓
┌────────────────────────────────────────────┐
│  Core Layer (Use Cases)                    │
│  ✅ PRIMARY USE OF RESULT PATTERN          │
│  - All use cases return Result             │
│  - Business rule violations = Err          │
│  - Success = Ok                            │
└──────────────────┬─────────────────────────┘
                   ↓
┌────────────────────────────────────────────┐
│  Domain Layer                              │
│  - Pure functions return Result            │
│  - Validation functions return Result      │
└──────────────────┬─────────────────────────┘
                   ↓
┌────────────────────────────────────────────┐
│  Data Layer                                │
│  ⚠️ MIXED: Result for expected failures    │
│  - User not found = Ok(null) or Err        │
│  - Database crash = throw exception        │
└────────────────────────────────────────────┘
```

### The Golden Rule

> **Use Result for expected failures (business errors).**
> **Use exceptions for unexpected failures (system errors).**

### Expected vs Unexpected Failures

| Expected (Use Result) | Unexpected (Use Exceptions) |
|----------------------|----------------------------|
| User already exists | Database connection failed |
| Invalid password | Out of memory |
| Email format invalid | Network timeout |
| Insufficient permissions | Disk full |
| Resource not found (when searched) | Programming error (null reference) |
| Business rule violation | Third-party API crash |

**Why?**
- **Expected failures** are part of the business domain and should be handled explicitly
- **Unexpected failures** indicate something is fundamentally wrong and should bubble up

### Result in Each Layer

#### Domain Layer

```typescript
// Domain: Pure validation returns Result
// src/features/auth/domain/rules/passwordRules.ts

export type PasswordError =
  | { type: "TOO_SHORT"; minLength: number }
  | { type: "MISSING_UPPERCASE" }
  | { type: "MISSING_NUMBER" }
  | { type: "MISSING_SPECIAL_CHAR" };

export class PasswordRules {
  static validate(password: string): Result<string, PasswordError> {
    if (password.length < 8) {
      return err({ type: "TOO_SHORT", minLength: 8 });
    }

    if (!/[A-Z]/.test(password)) {
      return err({ type: "MISSING_UPPERCASE" });
    }

    if (!/\d/.test(password)) {
      return err({ type: "MISSING_NUMBER" });
    }

    return ok(password);
  }
}
```

#### Core Layer (Use Cases)

```typescript
// Core: Use cases return Result
// src/features/auth/core/usecases/RegisterUser.ts

export type RegisterUserError =
  | { type: "INVALID_EMAIL"; email: string }
  | { type: "INVALID_PASSWORD"; error: PasswordError }
  | { type: "USER_ALREADY_EXISTS"; email: string }
  | { type: "EMAIL_SEND_FAILED"; reason: string };

export class RegisterUser {
  constructor(
    private userRepository: IUserRepository,
    private emailService: IEmailService
  ) {}

  async execute(data: CreateUserData): Promise<Result<User, RegisterUserError>> {
    // Validate password using domain rules
    const passwordValidation = PasswordRules.validate(data.password);
    if (!passwordValidation.isOk) {
      return err({ 
        type: "INVALID_PASSWORD", 
        error: passwordValidation.error 
      });
    }

    // Check if user exists
    const existingUser = await this.userRepository.findByEmail(data.email);
    if (existingUser) {
      return err({ 
        type: "USER_ALREADY_EXISTS", 
        email: data.email 
      });
    }

    // Create user
    const passwordHash = await Bun.password.hash(data.password);
    const user = await this.userRepository.create({
      ...data,
      password: passwordHash,
    });

    // Send verification email
    try {
      await this.emailService.sendVerificationEmail(user.email, user.id);
    } catch (error) {
      // Email failure is expected but not critical
      return err({ 
        type: "EMAIL_SEND_FAILED", 
        reason: error instanceof Error ? error.message : "Unknown" 
      });
    }

    return ok(user);
  }
}
```

#### Data Layer

```typescript
// Data: Mixed approach
// src/features/auth/data/repositories/DrizzleUserRepository.ts

export class DrizzleUserRepository implements IUserRepository {
  constructor(private db: Database) {}

  // Finding nothing is expected (not an error)
  async findByEmail(email: string): Promise<User | null> {
    try {
      const result = await this.db
        .select()
        .from(users)
        .where(eq(users.email, email))
        .limit(1);

      return result[0] || null;  // No result = null (expected)
    } catch (error) {
      // Database crash is unexpected
      throw new DatabaseError("Failed to query user", { cause: error });
    }
  }

  // Creation failure is unexpected (constraint violations are programming errors)
  async create(data: CreateUserData): Promise<User> {
    try {
      const result = await this.db
        .insert(users)
        .values({
          email: data.email,
          passwordHash: data.password,
          tenantId: data.tenantId,
        })
        .returning();

      return result[0];
    } catch (error) {
      // Unique constraint violation = programming error
      // (we should have checked before calling create)
      throw new DatabaseError("Failed to create user", { cause: error });
    }
  }
}
```

#### API Layer

```typescript
// API: Convert Result to HTTP response
// src/features/auth/api/AuthController.ts

export class AuthController {
  constructor(private registerUserUseCase: RegisterUser) {}

  routes() {
    return new Elysia({ prefix: "/auth" })
      .post("/register", async ({ body, set }) => {
        const result = await this.registerUserUseCase.execute(body);

        // Pattern match on result
        if (result.isOk) {
          set.status = 201;
          return {
            success: true,
            data: {
              id: result.value.id,
              email: result.value.email,
            },
          };
        }

        // Handle errors based on type
        const error = result.error;
        switch (error.type) {
          case "INVALID_PASSWORD":
            set.status = 400;
            return {
              success: false,
              error: {
                code: "INVALID_PASSWORD",
                message: this.formatPasswordError(error.error),
              },
            };

          case "USER_ALREADY_EXISTS":
            set.status = 409;
            return {
              success: false,
              error: {
                code: "USER_EXISTS",
                message: `User with email ${error.email} already exists`,
              },
            };

          case "EMAIL_SEND_FAILED":
            // User created but email failed - still return success
            set.status = 201;
            return {
              success: true,
              data: { /* ... */ },
              warning: "Email verification could not be sent",
            };

          default:
            // TypeScript ensures we handle all cases
            const _exhaustive: never = error;
            return _exhaustive;
        }
      }, {
        body: RegisterDto,
      });
  }

  private formatPasswordError(error: PasswordError): string {
    switch (error.type) {
      case "TOO_SHORT":
        return `Password must be at least ${error.minLength} characters`;
      case "MISSING_UPPERCASE":
        return "Password must contain an uppercase letter";
      case "MISSING_NUMBER":
        return "Password must contain a number";
      case "MISSING_SPECIAL_CHAR":
        return "Password must contain a special character";
    }
  }
}
```

---

## 4. Implementation Guide

### Step 1: Create the Result Type

Create the core Result type in `src/common/core/Result.ts`:

```typescript
// src/common/core/Result.ts

/**
 * Represents a successful result containing a value
 */
export class Ok<T> {
  readonly isOk = true;
  readonly isErr = false;

  constructor(readonly value: T) {}
}

/**
 * Represents a failed result containing an error
 */
export class Err<E> {
  readonly isOk = false;
  readonly isErr = true;

  constructor(readonly error: E) {}
}

/**
 * Result type that represents either success (Ok) or failure (Err)
 */
export type Result<T, E> = Ok<T> | Err<E>;

/**
 * Create a successful result
 */
export function ok<T>(value: T): Ok<T> {
  return new Ok(value);
}

/**
 * Create a failed result
 */
export function err<E>(error: E): Err<E> {
  return new Err(error);
}
```

### Step 2: Add Helper Methods (Optional)

Enhance the Result type with useful utilities:

```typescript
// src/common/core/Result.ts (continued)

/**
 * Helper functions for working with Results
 */
export namespace Result {
  /**
   * Map a Result's value if Ok, otherwise pass through the error
   */
  export function map<T, U, E>(
    result: Result<T, E>,
    fn: (value: T) => U
  ): Result<U, E> {
    return result.isOk ? ok(fn(result.value)) : result;
  }

  /**
   * FlatMap (chain) Results together
   */
  export function andThen<T, U, E>(
    result: Result<T, E>,
    fn: (value: T) => Result<U, E>
  ): Result<U, E> {
    return result.isOk ? fn(result.value) : result;
  }

  /**
   * Transform an error type
   */
  export function mapError<T, E, F>(
    result: Result<T, E>,
    fn: (error: E) => F
  ): Result<T, F> {
    return result.isErr ? err(fn(result.error)) : result;
  }

  /**
   * Get value or throw error
   * USE SPARINGLY - defeats the purpose of Result!
   */
  export function unwrap<T, E>(result: Result<T, E>): T {
    if (result.isOk) {
      return result.value;
    }
    throw new Error("Called unwrap on an Err value");
  }

  /**
   * Get value or return default
   */
  export function unwrapOr<T, E>(result: Result<T, E>, defaultValue: T): T {
    return result.isOk ? result.value : defaultValue;
  }

  /**
   * Combine multiple Results into one
   * Returns Ok with array of values if all are Ok
   * Returns first Err encountered otherwise
   */
  export function all<T, E>(
    results: Result<T, E>[]
  ): Result<T[], E> {
    const values: T[] = [];
    for (const result of results) {
      if (result.isErr) {
        return result;
      }
      values.push(result.value);
    }
    return ok(values);
  }

  /**
   * Check if Result is Ok
   */
  export function isOk<T, E>(result: Result<T, E>): result is Ok<T> {
    return result.isOk;
  }

  /**
   * Check if Result is Err
   */
  export function isErr<T, E>(result: Result<T, E>): result is Err<E> {
    return result.isErr;
  }
}
```

### Step 3: Define Domain Error Types

Create specific error types for your domain:

```typescript
// src/features/auth/domain/errors/AuthErrors.ts

/**
 * Password validation errors
 */
export type PasswordError =
  | { type: "TOO_SHORT"; minLength: number }
  | { type: "TOO_LONG"; maxLength: number }
  | { type: "MISSING_UPPERCASE" }
  | { type: "MISSING_LOWERCASE" }
  | { type: "MISSING_NUMBER" }
  | { type: "MISSING_SPECIAL_CHAR" }
  | { type: "CONTAINS_WHITESPACE" };

/**
 * Email validation errors
 */
export type EmailError =
  | { type: "INVALID_FORMAT"; email: string }
  | { type: "DISPOSABLE_EMAIL"; domain: string }
  | { type: "BLACKLISTED"; email: string };

/**
 * Registration errors
 */
export type RegisterUserError =
  | { type: "INVALID_EMAIL"; error: EmailError }
  | { type: "INVALID_PASSWORD"; error: PasswordError }
  | { type: "USER_ALREADY_EXISTS"; email: string }
  | { type: "TENANT_NOT_FOUND"; tenantId: string }
  | { type: "EMAIL_SEND_FAILED"; reason: string };

/**
 * Login errors
 */
export type LoginError =
  | { type: "INVALID_CREDENTIALS" }
  | { type: "EMAIL_NOT_VERIFIED"; userId: string }
  | { type: "ACCOUNT_LOCKED"; reason: string }
  | { type: "TENANT_MISMATCH" };

/**
 * Token errors
 */
export type TokenError =
  | { type: "INVALID_TOKEN"; reason: string }
  | { type: "TOKEN_EXPIRED"; expiredAt: Date }
  | { type: "TOKEN_REVOKED"; revokedAt: Date };
```

**Key Principles:**
- Use **discriminated unions** (each error has a `type` field)
- Include relevant context in each error
- Be specific (not just `{ type: "ERROR"; message: string }`)

### Step 4: Update Domain Rules

```typescript
// src/features/auth/domain/rules/passwordRules.ts

import { Result, ok, err } from "@/common/core/Result";
import { PasswordError } from "../errors/AuthErrors";

export class PasswordRules {
  static readonly MIN_LENGTH = 8;
  static readonly MAX_LENGTH = 128;

  static validate(password: string): Result<string, PasswordError> {
    if (password.length < this.MIN_LENGTH) {
      return err({ type: "TOO_SHORT", minLength: this.MIN_LENGTH });
    }

    if (password.length > this.MAX_LENGTH) {
      return err({ type: "TOO_LONG", maxLength: this.MAX_LENGTH });
    }

    if (!/[A-Z]/.test(password)) {
      return err({ type: "MISSING_UPPERCASE" });
    }

    if (!/[a-z]/.test(password)) {
      return err({ type: "MISSING_LOWERCASE" });
    }

    if (!/\d/.test(password)) {
      return err({ type: "MISSING_NUMBER" });
    }

    if (/\s/.test(password)) {
      return err({ type: "CONTAINS_WHITESPACE" });
    }

    return ok(password);
  }
}
```

### Step 5: Update Use Cases

```typescript
// src/features/auth/core/usecases/LoginUser.ts

import { Result, ok, err } from "@/common/core/Result";
import { LoginError } from "@/features/auth/domain/errors/AuthErrors";
import { IUserRepository } from "@/features/auth/domain/repositories/IUserRepository";
import { ITokenService } from "@/features/auth/domain/services/ITokenService";

export interface LoginCredentials {
  email: string;
  password: string;
  tenantId: string;
}

export interface LoginResult {
  accessToken: string;
  refreshToken: string;
  user: {
    id: string;
    email: string;
  };
}

export class LoginUser {
  constructor(
    private userRepository: IUserRepository,
    private tokenService: ITokenService
  ) {}

  async execute(
    credentials: LoginCredentials
  ): Promise<Result<LoginResult, LoginError>> {
    // Find user
    const user = await this.userRepository.findByEmail(
      credentials.email,
      credentials.tenantId
    );

    if (!user) {
      return err({ type: "INVALID_CREDENTIALS" });
    }

    // Verify tenant
    if (user.tenantId !== credentials.tenantId) {
      return err({ type: "TENANT_MISMATCH" });
    }

    // Verify password
    const isValidPassword = await Bun.password.verify(
      credentials.password,
      user.passwordHash
    );

    if (!isValidPassword) {
      return err({ type: "INVALID_CREDENTIALS" });
    }

    // Check email verification
    if (!user.emailVerified) {
      return err({ 
        type: "EMAIL_NOT_VERIFIED", 
        userId: user.id 
      });
    }

    // Generate tokens
    const accessToken = await this.tokenService.generateAccessToken(user.id);
    const refreshToken = await this.tokenService.generateRefreshToken(user.id);

    return ok({
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
      },
    });
  }
}
```

### Step 6: Handle Results in Controllers

```typescript
// src/features/auth/api/AuthController.ts

import { Elysia } from "elysia";
import { LoginUser } from "@/features/auth/core/usecases/LoginUser";
import { LoginDto } from "./dtos/LoginDto";

export class AuthController {
  constructor(private loginUserUseCase: LoginUser) {}

  routes() {
    return new Elysia({ prefix: "/auth" })
      .post("/login", async ({ body, set }) => {
        const result = await this.loginUserUseCase.execute({
          email: body.email,
          password: body.password,
          tenantId: body.tenantId,
        });

        if (result.isOk) {
          return {
            success: true,
            data: result.value,
          };
        }

        // Handle errors
        const error = result.error;
        switch (error.type) {
          case "INVALID_CREDENTIALS":
            set.status = 401;
            return {
              success: false,
              error: {
                code: "INVALID_CREDENTIALS",
                message: "Invalid email or password",
              },
            };

          case "EMAIL_NOT_VERIFIED":
            set.status = 403;
            return {
              success: false,
              error: {
                code: "EMAIL_NOT_VERIFIED",
                message: "Please verify your email before logging in",
                userId: error.userId,
              },
            };

          case "ACCOUNT_LOCKED":
            set.status = 403;
            return {
              success: false,
              error: {
                code: "ACCOUNT_LOCKED",
                message: `Account locked: ${error.reason}`,
              },
            };

          case "TENANT_MISMATCH":
            set.status = 400;
            return {
              success: false,
              error: {
                code: "TENANT_MISMATCH",
                message: "User does not belong to this tenant",
              },
            };

          default:
            // Exhaustiveness check - TypeScript error if we miss a case
            const _exhaustive: never = error;
            return _exhaustive;
        }
      }, {
        body: LoginDto,
      });
  }
}
```

---

## 5. Usage in Different Layers

### Domain Layer: Pure Validation

```typescript
// Domain rules return Result for validation
export class EmailRules {
  static validate(email: string): Result<string, EmailError> {
    // Check format
    if (!email.includes("@")) {
      return err({ type: "INVALID_FORMAT", email });
    }

    // Check disposable
    const domain = email.split("@")[1];
    if (this.isDisposable(domain)) {
      return err({ type: "DISPOSABLE_EMAIL", domain });
    }

    return ok(email);
  }

  private static isDisposable(domain: string): boolean {
    const disposableDomains = ["tempmail.com", "10minutemail.com"];
    return disposableDomains.includes(domain);
  }
}
```

### Core Layer: Use Case Orchestration

```typescript
// Use cases compose multiple Results
export class RegisterUser {
  async execute(data: CreateUserData): Promise<Result<User, RegisterUserError>> {
    // Validate email
    const emailValidation = EmailRules.validate(data.email);
    if (emailValidation.isErr) {
      return err({ 
        type: "INVALID_EMAIL", 
        error: emailValidation.error 
      });
    }

    // Validate password
    const passwordValidation = PasswordRules.validate(data.password);
    if (passwordValidation.isErr) {
      return err({ 
        type: "INVALID_PASSWORD", 
        error: passwordValidation.error 
      });
    }

    // Check tenant exists
    const tenant = await this.tenantRepository.findById(data.tenantId);
    if (!tenant) {
      return err({ 
        type: "TENANT_NOT_FOUND", 
        tenantId: data.tenantId 
      });
    }

    // Check user doesn't exist
    const existing = await this.userRepository.findByEmail(data.email);
    if (existing) {
      return err({ 
        type: "USER_ALREADY_EXISTS", 
        email: data.email 
      });
    }

    // Create user
    const hash = await Bun.password.hash(data.password);
    const user = await this.userRepository.create({
      ...data,
      password: hash,
    });

    return ok(user);
  }
}
```

### Data Layer: Mixed Approach

```typescript
// Repositories: null for "not found", exception for system errors
export class DrizzleUserRepository implements IUserRepository {
  async findByEmail(email: string): Promise<User | null> {
    try {
      const users = await this.db
        .select()
        .from(usersTable)
        .where(eq(usersTable.email, email))
        .limit(1);
      
      return users[0] || null;  // Not found is expected
    } catch (error) {
      // Database error is unexpected
      throw new DatabaseError("Failed to find user", { cause: error });
    }
  }

  async create(data: CreateUserData): Promise<User> {
    // Creation failure is unexpected (should be caught earlier)
    const result = await this.db
      .insert(usersTable)
      .values(data)
      .returning();
    
    return result[0];
  }
}
```

### API Layer: Result to HTTP

```typescript
// Helper function to convert Result to HTTP response
function toHttpResponse<T, E>(
  result: Result<T, E>,
  errorMapper: (error: E) => { status: number; body: any }
): { status: number; body: any } {
  if (result.isOk) {
    return {
      status: 200,
      body: { success: true, data: result.value },
    };
  }

  return errorMapper(result.error);
}

// Usage in controller
.post("/register", async ({ body, set }) => {
  const result = await this.registerUserUseCase.execute(body);
  
  const response = toHttpResponse(result, (error) => {
    switch (error.type) {
      case "USER_ALREADY_EXISTS":
        return {
          status: 409,
          body: {
            success: false,
            error: {
              code: "USER_EXISTS",
              message: `User ${error.email} already exists`,
            },
          },
        };
      
      case "INVALID_PASSWORD":
        return {
          status: 400,
          body: {
            success: false,
            error: {
              code: "INVALID_PASSWORD",
              message: formatPasswordError(error.error),
            },
          },
        };
      
      // ... other cases
    }
  });

  set.status = response.status;
  return response.body;
})
```

---

## 6. Best Practices for Bun/Elysia Projects

### 1. Use Discriminated Unions

Always use discriminated unions for error types:

```typescript
// ✅ Good: Discriminated union
type LoginError =
  | { type: "INVALID_CREDENTIALS" }
  | { type: "EMAIL_NOT_VERIFIED"; userId: string }
  | { type: "ACCOUNT_LOCKED"; reason: string };

// ❌ Bad: Plain strings
type LoginError = "INVALID_CREDENTIALS" | "EMAIL_NOT_VERIFIED" | "ACCOUNT_LOCKED";
```

**Why?** TypeScript can exhaustively check all cases and error details are type-safe.

### 2. Organize Errors by Feature

```
features/auth/
├── domain/
│   └── errors/
│       ├── AuthErrors.ts       # All auth-related errors
│       ├── PasswordErrors.ts   # Specific to passwords
│       └── TokenErrors.ts      # Specific to tokens
```

### 3. Create Error Helper Functions

```typescript
// src/features/auth/domain/errors/helpers.ts

export function isPasswordError(
  error: RegisterUserError
): error is { type: "INVALID_PASSWORD"; error: PasswordError } {
  return error.type === "INVALID_PASSWORD";
}

export function formatPasswordError(error: PasswordError): string {
  switch (error.type) {
    case "TOO_SHORT":
      return `Password must be at least ${error.minLength} characters`;
    case "MISSING_UPPERCASE":
      return "Password must contain an uppercase letter";
    // ... other cases
  }
}
```

### 4. Use Helper Methods for Composition

```typescript
// Chain validations
const result = await Result.andThen(
  EmailRules.validate(email),
  async (validEmail) => {
    const user = await userRepository.findByEmail(validEmail);
    return user ? err({ type: "EXISTS" }) : ok(validEmail);
  }
);
```

### 5. Combine Multiple Results

```typescript
// Validate multiple fields
const emailResult = EmailRules.validate(data.email);
const passwordResult = PasswordRules.validate(data.password);

// Collect all errors
const errors: ValidationError[] = [];
if (emailResult.isErr) errors.push({ field: "email", ...emailResult.error });
if (passwordResult.isErr) errors.push({ field: "password", ...passwordResult.error });

if (errors.length > 0) {
  return err({ type: "VALIDATION_FAILED", errors });
}
```

### 6. Document Error Types

```typescript
/**
 * Registers a new user in the system.
 *
 * @returns Ok(User) if registration succeeds
 * @returns Err with:
 *   - INVALID_EMAIL: Email format is invalid
 *   - INVALID_PASSWORD: Password doesn't meet requirements
 *   - USER_ALREADY_EXISTS: Email is already registered
 *   - TENANT_NOT_FOUND: Specified tenant doesn't exist
 */
async execute(data: CreateUserData): Promise<Result<User, RegisterUserError>>
```

### 7. Use Type Guards

```typescript
function isValidationError(
  error: RegisterUserError
): error is { type: "INVALID_EMAIL" } | { type: "INVALID_PASSWORD" } {
  return error.type === "INVALID_EMAIL" || error.type === "INVALID_PASSWORD";
}

// Usage
if (result.isErr && isValidationError(result.error)) {
  // Handle validation errors specifically
}
```

### 8. Create Reusable Error Mappers for Elysia

```typescript
// src/common/api/errorMappers.ts

export function mapAuthErrorToHttp(error: LoginError): {
  status: number;
  code: string;
  message: string;
} {
  switch (error.type) {
    case "INVALID_CREDENTIALS":
      return {
        status: 401,
        code: "INVALID_CREDENTIALS",
        message: "Invalid email or password",
      };
    
    case "EMAIL_NOT_VERIFIED":
      return {
        status: 403,
        code: "EMAIL_NOT_VERIFIED",
        message: "Please verify your email",
      };
    
    // ... other cases
  }
}

// Usage in controller
if (result.isErr) {
  const { status, code, message } = mapAuthErrorToHttp(result.error);
  set.status = status;
  return { success: false, error: { code, message } };
}
```

### 9. Leverage Bun's Performance

```typescript
// Bun's native password hashing is fast - use it!
const hash = await Bun.password.hash(password, {
  algorithm: "argon2id",
  memoryCost: 19456,
  timeCost: 2,
});

const isValid = await Bun.password.verify(password, hash);
```

### 10. Global Error Handler for Unexpected Errors

```typescript
// src/common/middleware/errorHandler.ts

export const errorHandler = (app: Elysia) =>
  app.onError(({ code, error, set }) => {
    // System errors (exceptions) that bubble up
    if (code === "UNKNOWN") {
      console.error("Unexpected error:", error);
      set.status = 500;
      return {
        success: false,
        error: {
          code: "INTERNAL_ERROR",
          message: "An unexpected error occurred",
        },
      };
    }

    // Validation errors from Elysia
    if (code === "VALIDATION") {
      set.status = 400;
      return {
        success: false,
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid request data",
          details: error,
        },
      };
    }

    // Other codes...
  });
```

---

## 7. Common Patterns & Recipes

### Pattern 1: Early Return

```typescript
async execute(data: LoginData): Promise<Result<Token, LoginError>> {
  // Validate input
  const emailValidation = EmailRules.validate(data.email);
  if (emailValidation.isErr) {
    return err({ type: "INVALID_EMAIL", error: emailValidation.error });
  }

  // Check user exists
  const user = await this.userRepository.findByEmail(data.email);
  if (!user) {
    return err({ type: "INVALID_CREDENTIALS" });
  }

  // Verify password
  const isValid = await this.verifyPassword(data.password, user.passwordHash);
  if (!isValid) {
    return err({ type: "INVALID_CREDENTIALS" });
  }

  // All good
  const token = await this.tokenService.generate(user.id);
  return ok(token);
}
```

### Pattern 2: Collecting Multiple Errors

```typescript
type FieldError = { field: string; message: string };

function validateRegistration(
  data: RegisterData
): Result<RegisterData, FieldError[]> {
  const errors: FieldError[] = [];

  const emailValidation = EmailRules.validate(data.email);
  if (emailValidation.isErr) {
    errors.push({
      field: "email",
      message: formatEmailError(emailValidation.error),
    });
  }

  const passwordValidation = PasswordRules.validate(data.password);
  if (passwordValidation.isErr) {
    errors.push({
      field: "password",
      message: formatPasswordError(passwordValidation.error),
    });
  }

  if (errors.length > 0) {
    return err(errors);
  }

  return ok(data);
}
```

### Pattern 3: Chaining Operations

```typescript
async execute(email: string): Promise<Result<void, SendEmailError>> {
  return await Result.andThen(
    EmailRules.validate(email),
    async (validEmail) => {
      const user = await this.userRepository.findByEmail(validEmail);
      return user 
        ? ok(user) 
        : err({ type: "USER_NOT_FOUND", email: validEmail });
    }
  ).then((result) =>
    Result.andThen(result, async (user) => {
      const token = await this.tokenService.generateVerification(user.id);
      return await this.emailService.send(user.email, token);
    })
  );
}
```

### Pattern 4: Converting Exceptions to Results

```typescript
async function tryAsync<T>(
  fn: () => Promise<T>
): Promise<Result<T, Error>> {
  try {
    const value = await fn();
    return ok(value);
  } catch (error) {
    return err(error instanceof Error ? error : new Error(String(error)));
  }
}

// Usage
const result = await tryAsync(() => 
  fetch("https://api.example.com/user").then(r => r.json())
);

if (result.isErr) {
  console.error("API call failed:", result.error.message);
}
```

### Pattern 5: Result in Middleware

```typescript
// src/common/middleware/auth.ts

type AuthResult = Result<{ userId: string }, AuthError>;

async function authenticate(token: string): Promise<AuthResult> {
  if (!token) {
    return err({ type: "MISSING_TOKEN" });
  }

  try {
    const payload = await verifyJwt(token);
    return ok({ userId: payload.sub });
  } catch (error) {
    return err({ type: "INVALID_TOKEN" });
  }
}

// Elysia middleware
export const authMiddleware = (app: Elysia) =>
  app.derive(async ({ headers, set }) => {
    const token = headers.authorization?.replace("Bearer ", "");
    const result = await authenticate(token);

    if (result.isErr) {
      set.status = 401;
      throw new Error("Unauthorized");
    }

    return { user: result.value };
  });
```

### Pattern 6: Option Type for Nullable Values

```typescript
// Sometimes you want to distinguish "not found" from "error"
type Option<T> = { some: true; value: T } | { some: false };

function some<T>(value: T): Option<T> {
  return { some: true, value };
}

function none<T>(): Option<T> {
  return { some: false };
}

// Repository returns Option instead of null
async findByEmail(email: string): Promise<Option<User>> {
  const user = await this.db.query.users.findFirst({
    where: eq(users.email, email),
  });

  return user ? some(user) : none();
}
```

---

## 8. Testing with Result Pattern

### Testing Use Cases

```typescript
// tests/auth/RegisterUser.test.ts

import { describe, it, expect } from "bun:test";
import { RegisterUser } from "@/features/auth/core/usecases/RegisterUser";
import { MockUserRepository } from "./mocks/MockUserRepository";
import { MockEmailService } from "./mocks/MockEmailService";

describe("RegisterUser", () => {
  it("should succeed with valid data", async () => {
    const userRepo = new MockUserRepository();
    const emailService = new MockEmailService();
    const useCase = new RegisterUser(userRepo, emailService);

    const result = await useCase.execute({
      email: "test@example.com",
      password: "SecurePass123",
      tenantId: "tenant-1",
    });

    // No try-catch needed!
    expect(result.isOk).toBe(true);
    if (result.isOk) {
      expect(result.value.email).toBe("test@example.com");
    }
  });

  it("should fail with weak password", async () => {
    const userRepo = new MockUserRepository();
    const emailService = new MockEmailService();
    const useCase = new RegisterUser(userRepo, emailService);

    const result = await useCase.execute({
      email: "test@example.com",
      password: "weak",  // Too short
      tenantId: "tenant-1",
    });

    expect(result.isErr).toBe(true);
    if (result.isErr) {
      expect(result.error.type).toBe("INVALID_PASSWORD");
      if (result.error.type === "INVALID_PASSWORD") {
        expect(result.error.error.type).toBe("TOO_SHORT");
      }
    }
  });

  it("should fail when user exists", async () => {
    const userRepo = new MockUserRepository();
    const emailService = new MockEmailService();
    const useCase = new RegisterUser(userRepo, emailService);

    // Pre-populate repository
    await userRepo.create({
      email: "existing@example.com",
      password: "hash",
      tenantId: "tenant-1",
    });

    const result = await useCase.execute({
      email: "existing@example.com",
      password: "SecurePass123",
      tenantId: "tenant-1",
    });

    expect(result.isErr).toBe(true);
    if (result.isErr) {
      expect(result.error.type).toBe("USER_ALREADY_EXISTS");
      if (result.error.type === "USER_ALREADY_EXISTS") {
        expect(result.error.email).toBe("existing@example.com");
      }
    }
  });
});
```

### Testing Domain Rules

```typescript
// tests/domain/PasswordRules.test.ts

import { describe, it, expect } from "bun:test";
import { PasswordRules } from "@/features/auth/domain/rules/passwordRules";

describe("PasswordRules", () => {
  it("should accept valid password", () => {
    const result = PasswordRules.validate("SecurePass123");
    
    expect(result.isOk).toBe(true);
    if (result.isOk) {
      expect(result.value).toBe("SecurePass123");
    }
  });

  it("should reject short password", () => {
    const result = PasswordRules.validate("Short1");
    
    expect(result.isErr).toBe(true);
    if (result.isErr) {
      expect(result.error.type).toBe("TOO_SHORT");
      if (result.error.type === "TOO_SHORT") {
        expect(result.error.minLength).toBe(8);
      }
    }
  });

  it("should reject password without uppercase", () => {
    const result = PasswordRules.validate("securepass123");
    
    expect(result.isErr).toBe(true);
    if (result.isErr) {
      expect(result.error.type).toBe("MISSING_UPPERCASE");
    }
  });
});
```

### Testing Controllers

```typescript
// tests/api/AuthController.test.ts

import { describe, it, expect } from "bun:test";
import { Elysia } from "elysia";
import { AuthController } from "@/features/auth/api/AuthController";
import { MockRegisterUser } from "./mocks/MockRegisterUser";

describe("AuthController", () => {
  it("POST /register should return 201 on success", async () => {
    const registerUseCase = new MockRegisterUser();
    const controller = new AuthController(registerUseCase);
    
    const app = new Elysia().use(controller.routes());

    const response = await app.handle(
      new Request("http://localhost/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "test@example.com",
          password: "SecurePass123",
          tenantId: "tenant-1",
        }),
      })
    );

    expect(response.status).toBe(201);
    const body = await response.json();
    expect(body.success).toBe(true);
  });

  it("POST /register should return 409 when user exists", async () => {
    const registerUseCase = new MockRegisterUser({
      forceError: { type: "USER_ALREADY_EXISTS", email: "test@example.com" },
    });
    const controller = new AuthController(registerUseCase);
    
    const app = new Elysia().use(controller.routes());

    const response = await app.handle(
      new Request("http://localhost/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "test@example.com",
          password: "SecurePass123",
          tenantId: "tenant-1",
        }),
      })
    );

    expect(response.status).toBe(409);
    const body = await response.json();
    expect(body.success).toBe(false);
    expect(body.error.code).toBe("USER_EXISTS");
  });
});
```

---

## Summary

### Key Takeaways

| Concept | Description |
|---------|-------------|
| **Result Pattern** | Return `Result<T, E>` instead of throwing exceptions for expected failures |
| **Type Safety** | Compiler enforces error handling, impossible to ignore errors |
| **Expected vs Unexpected** | Use Result for business errors, exceptions for system errors |
| **Discriminated Unions** | Error types are unions with `type` field for exhaustive checking |
| **Composability** | Chain Results with `map`, `andThen`, combine with `all` |
| **Testability** | No try-catch in tests, just check `isOk` or `isErr` |

### When to Use Result

✅ **Use Result for:**
- User input validation
- Business rule violations
- Resource not found (when searched for)
- Authentication/authorization failures
- External API failures (expected)

❌ **Use Exceptions for:**
- Database connection failures
- Out of memory errors
- Programming errors (null reference, type errors)
- Unexpected system failures

### The Pattern in One Picture

```
┌────────────────────────────────────────────────────┐
│ Domain Layer                                       │
│ PasswordRules.validate(password)                   │
│ → Result<string, PasswordError>                    │
└────────────────┬───────────────────────────────────┘
                 ↓
┌────────────────────────────────────────────────────┐
│ Core Layer                                         │
│ RegisterUser.execute(data)                         │
│ → Result<User, RegisterUserError>                  │
└────────────────┬───────────────────────────────────┘
                 ↓
┌────────────────────────────────────────────────────┐
│ API Layer                                          │
│ AuthController.post("/register")                   │
│ → HTTP Response (200, 400, 409, etc.)              │
└────────────────────────────────────────────────────┘
```

### Benefits Recap

| Before (Exceptions) | After (Result) |
|---------------------|----------------|
| ❌ Hidden failures | ✅ Explicit in signature |
| ❌ Runtime type checks | ✅ Compile-time type checks |
| ❌ Easy to ignore errors | ✅ Impossible to ignore |
| ❌ Unclear error types | ✅ Documented error types |
| ❌ Try-catch everywhere | ✅ Clean if-else checks |
| ❌ Difficult to compose | ✅ Chainable operations |

---

## Next Steps

1. **Implement Result Type**: Create `src/common/core/Result.ts` with the base types
2. **Define Error Types**: Create domain-specific error types in each feature
3. **Update Domain Rules**: Make validation functions return `Result`
4. **Update Use Cases**: Make all use cases return `Result`
5. **Update Controllers**: Handle Results and convert to HTTP responses
6. **Write Tests**: Test both success and failure paths easily

---

**You're now ready to implement robust, type-safe error handling in your Bun/Elysia application! 🚀**

