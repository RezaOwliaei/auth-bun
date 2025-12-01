# Features & Implementation Briefs

This document lists the key features of our FusionAuth clone and provides a high-level guide on how to implement them.

## 1. Multi-Tenancy (Tenants)
FusionAuth is built around Tenants. A Tenant is a logical isolation of users and configurations.
-   **Concept**: Every request usually belongs to a Tenant.
-   **Data**: `tenants` table (id, name, issuer, jwt_configuration).
-   **Implementation**:
    -   Create a `Default Tenant` on startup if none exists.
    -   API requests should identify the tenant (via Header `X-FusionAuth-TenantId` or API Key).

## 2. User Management
Core identity management.
-   **Data**: `users` table (id, tenant_id, email, password_hash, salt, first_name, last_name, birth_date).
-   **Features**:
    -   **Registration**: Validate email, hash password (Argon2), store user.
    -   **Retrieve**: Get user by ID or Email.
    -   **Update**: Change profile data.
    -   **Delete**: Soft or hard delete.
    -   **Search**: Simple search by email/name.

## 3. Authentication (Login)
Verifying identity and issuing tokens.
-   **Flow**:
    1.  User sends Email + Password + TenantId.
    2.  Find user in DB for that Tenant.
    3.  Verify password hash.
    4.  Generate **Access Token** (JWT) and **Refresh Token**.
    5.  Return tokens.

## 4. JWT (JSON Web Tokens)
Stateless authentication.
-   **Library**: `jose` or Bun's built-in crypto (or Elysia's jwt plugin).
-   **Structure**: Header, Payload (sub=userId, iss=tenant, roles, exp), Signature.
-   **Signing**: Use RS256 (Public/Private Key pair) per Tenant.
    -   *Advanced*: Store keys in a `keys` table. For simplicity, we might start with HS256 (Shared Secret).

## 5. Refresh Tokens
Long-lived sessions.
-   **Data**: `refresh_tokens` table (token, user_id, device_info, expiry).
-   **Flow**:
    -   Access Token expires (short life, e.g., 5 min).
    -   Client sends Refresh Token.
    -   Server validates Refresh Token in DB (check if revoked/expired).
    -   Server issues new Access Token.

## 6. Roles & Permissions (RBAC)
Controlling access.
-   **Data**:
    -   `roles` table (id, name, description).
    -   `user_registrations` or `user_roles` table linking User <-> Role <-> Application.
-   **Implementation**:
    -   Add roles to JWT claims.
    -   Middleware checks if user has required role for an endpoint.

## 7. Applications (Optional/Advanced)
FusionAuth allows users to register for specific "Applications" within a Tenant.
-   **Data**: `applications` table.
-   **Relation**: Users have a `registration` for an Application.

---

## Implementation Priority
1.  **Foundation**: Database connection, Basic API setup.
2.  **Tenants**: Basic CRUD for Tenants (need at least one to create users).
3.  **Users**: Create (Register) and Login.
4.  **Security**: Password Hashing & JWT generation.
5.  **Middleware**: Auth Guard (protect routes).
