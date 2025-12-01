# Branded Types (Nominal Typing)

This guide explains the concept of **Branded Types** (also known as Opaque Types), a powerful TypeScript pattern used in this project to enforce type safety at the domain level.

---

## 1. The Problem: Structural Typing & Primitive Obsession

TypeScript uses **Structural Typing** (duck typing). This means if two types have the same structure, they are considered compatible.

While this is great for general development, it becomes dangerous when dealing with **Domain Primitives** (IDs, Emails, Money, etc.) that share the same underlying JavaScript type (usually `string` or `number`).

### The "Argument Swap" Bug

Consider this scenario:

```typescript
// Both are just strings
type UserId = string;
type TenantId = string;

function removeUserFromTenant(userId: UserId, tenantId: TenantId) {
  console.log(`Removing User ${userId} from Tenant ${tenantId}`);
}

const myUser = "user_123";
const myTenant = "tenant_456";

// ❌ BUG: Arguments are swapped!
// TypeScript compiles this happily because string === string.
removeUserFromTenant(myTenant, myUser);
```

This class of bugs is subtle, hard to spot in code reviews, and can lead to disastrous data corruption (e.g., deleting the wrong entity).

---

## 2. The Solution: Branded Types

**Branded Types** allow us to simulate **Nominal Typing** (where types are distinguished by their name, not their structure) within TypeScript.

We achieve this by intersecting a primitive type (like `string`) with a unique "tag" or "brand" that doesn't actually exist at runtime.

### The `Brand` Utility

We define a generic utility helper:

```typescript
// src/common/types/Brand.ts

/**
 * Creates a Branded Type.
 * 
 * @template K - The underlying primitive type (string, number, etc.)
 * @template T - The unique literal tag for this brand
 */
export type Brand<K, T> = K & { readonly __brand: T };

/**
 * "Blesses" a primitive value as a Branded Type.
 * Use this ONLY at the boundaries of your application (Presentation/Infrastructure).
 * 
 * T is the Branded Type (e.g., UserId)
 * We infer 'K' (the primitive) from 'T' to ensure the input matches.
 */
export function make<T extends Brand<any, any>>(
  value: T extends Brand<infer K, any> ? K : never
): T {
  return value as T;
}
```

#### 🎓 Beginner's Guide: How `make` Works

If the syntax above looks scary, don't worry! Here is a line-by-line breakdown of what is happening in that function signature:

1.  **`T extends Brand<any, any>`**:
    *   This tells TypeScript: "You can't just pass *anything* to `make`. You must tell me specifically which **Branded Type** you want to create (like `UserId` or `Email`)."
    *   Usage: `make<UserId>(...)`

2.  **`value: T extends Brand<infer K, any> ? K : never`**:
    *   This is a **Conditional Type** (like an `if` statement for types).
    *   It asks: "Look at the `T` you passed in (e.g., `UserId`). What was the original primitive type used to make it?"
    *   **`infer K`**: "Grab that primitive type and call it `K`." (If `UserId` is a branded string, `K` becomes `string`).
    *   **`? K`**: "If we successfully found `K`, then the `value` argument MUST be of type `K`."
    *   **Result**: If you try to do `make<UserId>(123)`, TypeScript sees that `UserId` is based on `string`, but you passed a `number`. It will yell at you with a red squiggly line.

**Why is this better?**
The previous version used `value: any`, which allowed you to pass *anything* (even a number into a string brand). This version uses **Type Inference** to ensure you only pass the correct primitive type, catching bugs *before* you run the code.

### Defining Domain Types

Now we can define distinct types that are incompatible with each other:

```typescript
export type UserId = Brand<string, "UserId">;
export type TenantId = Brand<string, "TenantId">;
export type Email = Brand<string, "Email">;
```

---

## 3. How It Works

### Compile-Time Safety

If we try the same bug again:

```typescript
function removeUserFromTenant(userId: UserId, tenantId: TenantId) { ... }

const myUser = "user_123" as UserId;
const myTenant = "tenant_456" as TenantId;

// ❌ COMPILE ERROR:
// Argument of type 'TenantId' is not assignable to parameter of type 'UserId'.
// Type '"TenantId"' is not assignable to type '"UserId"'.
removeUserFromTenant(myTenant, myUser);
```

TypeScript now sees `UserId` and `TenantId` as completely different types, preventing accidental mixing.

### Runtime Behavior (Zero Overhead)

The `__brand` property is a **compile-time phantom**. It never exists at runtime.

```typescript
const id: UserId = "user_123" as UserId;

console.log(id); // Output: "user_123"
console.log(typeof id); // Output: "string"
```

Because `Brand<K, T>` is just an intersection (`&`), the runtime JavaScript is exactly the same as using a plain string. There is **zero performance penalty**.

---

## 4. Creating and Casting

Since a plain string is not a `UserId`, we need a way to "cast" or "validate" data into these types. Use the following decision guide:

### 1. Use `make` (The "Blessing" Function)

Use `make` when **Structure == Validity**. This applies to:
*   **IDs**: If it's a string, it's a valid ID format. Whether it *exists* in the DB is an application problem, not a type problem.
*   **Trusted Data**: Data coming from your database or internal services.

```typescript
// ✅ Controller: ID from HTTP request (Format validated by TypeBox)
const userId = make<UserId>(body.id);

// ✅ Repository: ID from Database
const userId = make<UserId>(row.id);
```

### 2. Use Factory Methods (Validation)

Use Factory Methods (`create()`) when **Structure != Validity**. This applies to:
*   **Value Objects**: Emails, Passwords, Money, Coordinates.
*   Just because it's a string doesn't mean it's a valid Email. It needs logic checks (regex, length, etc.).

```typescript
// Example: Email Value Object
export class Email {
  private constructor(public readonly value: string) {}

  // ❌ Don't use make() for Emails!
  // ✅ Use a static factory that returns a Result
  static create(email: string): Result<Email, AppError> {
    if (!email.includes("@")) {
      return err(AppError.validation("Invalid email"));
    }
    // We know it's valid, so we "bless" it as an Email type
    return ok(new Email(email));
  }
}

// Usage in Application Layer
const emailResult = Email.create(input.email);
if (emailResult.isErr()) return err(emailResult.error);
```

---

## 5. Integration with Libraries

### Drizzle ORM

Drizzle works seamlessly with branded types if you treat them as their underlying primitive.

```typescript
// schema.ts
export const users = pgTable("users", {
  // Drizzle sees this as varchar (string)
  id: varchar("id").primaryKey(), 
});

// repository.ts
async findById(id: UserId) {
  // We can pass UserId to where(eq(users.id, ...)) 
  // because UserId is a subtype of string.
  return db.select().from(users).where(eq(users.id, id));
}
```

### Elysia / TypeBox

When defining API schemas, we treat them as primitives but can add metadata.

```typescript
import { t } from "elysia";
import { make } from "@/common/types/Brand";

// The API receives a string
export const UserSchema = t.Object({
  id: t.String(),
  email: t.String({ format: "email" })
});

// In the controller/mapper, we cast to our Domain Types
// const userId = body.id as UserId;
const userId = make<UserId>(body.id);
```

---

## 6. Best Practices

1.  **Use for IDs**: Always brand your IDs (`UserId`, `OrderId`, `ProductId`). It is the highest ROI usage of branding.
2.  **Use for Money**: `Brand<number, "USD">` vs `Brand<number, "EUR">` prevents adding different currencies.
3.  **Don't Overuse**: Don't brand every single string (e.g., `FirstName`, `LastName`). Use it where type confusion is a risk or where the domain concept is distinct.
4.  **Centralize**: Keep your brand definitions in `src/common/types` or within their respective Feature Domain layers.

## 7. Real-World Production Example

Let's look at a complete, production-ready example following our **Feature-First Clean Architecture**. We'll implement a `GetUser` feature where the `UserId` is strictly branded throughout the system.

### 1. Common Types (`src/common/types/Brand.ts`)

First, the core utility.

```typescript
// src/common/types/Brand.ts
export type Brand<K, T> = K & { readonly __brand: T };

/**
 * "Blesses" a primitive value as a Branded Type.
 * Use this ONLY at the boundaries of your application (Presentation/Infrastructure).
 * 
 * T is the Branded Type (e.g., UserId)
 * We infer 'K' (the primitive) from 'T' to ensure the input matches.
 */
export function make<T extends Brand<any, any>>(
  value: T extends Brand<infer K, any> ? K : never
): T {
  return value as T;
}
```



### 2. Domain Layer (`src/features/users/domain/`)

Here we define our branded types and the Entity that uses them.

```typescript
// src/features/users/domain/types.ts
import { Brand } from "@/common/types/Brand";

export type UserId = Brand<string, "UserId">;
export type Email = Brand<string, "Email">;
```

```typescript
// src/features/users/domain/entities/User.ts
import { UserId, Email } from "../types";

export class User {
  constructor(
    public readonly id: UserId,
    public readonly email: Email,
    public readonly name: string
  ) {}

  // Factory for NEW users (validates business rules)
  static create(id: UserId, email: Email, name: string): User {
    // ... validation logic ...
    return new User(id, email, name);
  }

  // Factory for REHYDRATING users from DB (trusted)
  static restore(id: string, email: string, name: string): User {
    return new User(
      id as UserId,     // Cast trusted DB string to UserId
      email as Email,   // Cast trusted DB string to Email
      name
    );
  }
}
```

### 3. Application Layer (`src/features/users/application/`)

The Use Case defines the contract (Port) using the Branded Type. This forces any implementation to respect the type.

```typescript
// src/features/users/application/ports/IUserRepository.ts
import { User } from "../../domain/entities/User";
import { UserId } from "../../domain/types";

export interface IUserRepository {
  findById(id: UserId): Promise<User | null>;
}
```

```typescript
// src/features/users/application/usecases/GetUser.ts
import { IUserRepository } from "../ports/IUserRepository";
import { UserId } from "../../domain/types";
import { User } from "../../domain/entities/User";
import { Result, ok, err } from "@/common/error/Result";

export class GetUser {
  constructor(private readonly userRepository: IUserRepository) {}

  // The input MUST be a UserId. The caller is responsible for validation/casting.
  async execute(id: UserId): Promise<Result<User, Error>> {
    const user = await this.userRepository.findById(id);
    
    if (!user) {
      return err(new Error("User not found"));
    }
    
    return ok(user);
  }
}
```

### 4. Infrastructure Layer (`src/features/users/infrastructure/`)

The implementation deals with the "dirty" outside world (database) and maps it to the clean Domain.

```typescript
// src/features/users/infrastructure/repositories/DrizzleUserRepository.ts
import { IUserRepository } from "../../application/ports/IUserRepository";
import { UserId } from "../../domain/types";
import { User } from "../../domain/entities/User";
import { db } from "@/common/db";
import { users } from "../schema";
import { eq } from "drizzle-orm";

export class DrizzleUserRepository implements IUserRepository {
  async findById(id: UserId): Promise<User | null> {
    // Drizzle accepts the string because UserId is a subtype of string
    const row = await db.select().from(users).where(eq(users.id, id)).get();
    
    if (!row) return null;

    // Rehydrate using the restore method (trusted source)
    return User.restore(row.id, row.email, row.name);
  }
}
```

### 5. Presentation Layer (`src/features/users/presentation/`)

This is the **boundary** where the raw string from the HTTP request is validated and turned into a `UserId`.

```typescript
// src/features/users/presentation/http/UserController.ts
import { make } from "@/common/types/Brand";
import { UserId } from "../../domain/types";

// ... inside your route handler ...
async function handleGetUser(params: { id: string }) {
  // 1. Input is a plain string (validated by framework/TypeBox)
  const rawId = params.id;

  // 2. CAST: This is the "Safety Boundary"
  // We take the raw string and "bless" it as a UserId
  const userId = make<UserId>(rawId);

  // 3. Execute Use Case
  // The use case *requires* UserId, so we can't pass a raw string or an Email
  return getUserUseCase.execute(userId);
}
```

### Why this is "Production Ready"

1.  **Boundary Validation**: We only cast to `UserId` at the edges (Presentation for input, Infrastructure for DB loading).
2.  **Type Safety Core**: The Application and Domain layers *never* see a plain string. They are guaranteed to work with valid IDs.
3.  **Impossible Bugs**: You cannot accidentally pass an `Email` to `findById(id: UserId)`.
4.  **Clean Architecture**: Dependencies point inward. The Domain doesn't know about Drizzle or HTTP.

## Summary

| Feature | Structural Typing (Standard) | Branded Typing |
| :--- | :--- | :--- |
| **Type Check** | Based on shape | Based on name/tag |
| **Safety** | Low for primitives | High |
| **Runtime Cost** | None | None |
| **Developer Experience** | Easy | Requires casting/validation |
| **Use Case** | General data | Domain Primitives (IDs, Codes) |
