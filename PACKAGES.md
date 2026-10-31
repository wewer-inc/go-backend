# Package & Folder Guide

Short, opinionated conventions for naming and structuring packages in this boilerplate.

---

## Folder layout

```
.
├── cmd/server/                   # Binary entry point. Wires app.Build() + signal handling. No logic.
└── internal/
    ├── api/
    │   ├── adminaudit/           # Read and verify the audit trail
    │   ├── auth/                 # Sign-in, sessions, passwords, two-factor, "login as"
    │   ├── common/               # Shared response envelope and request binding
    │   ├── example/              # Example Note CRUD — copy-paste template for new features
    │   └── users/                # Admin role changes
    ├── apierr/                   # Typed API errors with HTTP status codes
    ├── app/                      # Dependency injection root: app.Build() wires everything
    ├── entities/
    │   ├── role.go               # Typed Role constants (RoleUser, RoleAdmin, RoleSupport)
    │   ├── audit/                # Audit trail rows and event names
    │   ├── loginfailure/         # Failed sign-in counters behind lockout
    │   ├── mfa/                  # TOTP enrollment, challenges, backup codes
    │   ├── passwordhistory/      # Previous password hashes
    │   ├── passwordreset/        # Single-use reset tokens
    │   ├── session/              # Sessions and retired refresh tokens
    │   ├── user/                 # User entity
    │   └── note/                 # Example entity
    ├── http/
    │   ├── middleware/           # Request ID, logger, auth, permission gates, body checks
    │   │   └── ratelimit/        # GCRA rate limiter middleware backed by Redis
    │   └── server/               # NewRouter: wires all middleware and feature routes
    ├── platform/
    │   ├── auditlog/             # Hash-chained audit recorder and verifier
    │   ├── auth/                 # JWT verifier + issuer, opaque tokens, password policy
    │   ├── authz/                # Pure access policy: matrix, scope, capabilities
    │   ├── config/               # Config struct loaded from environment variables
    │   ├── crypto/               # AES-GCM for secrets at rest
    │   ├── db/                   # GORM + PostgreSQL setup, migration runner, SQL log redaction
    │   ├── dbstats/              # Per-request query count and time
    │   ├── email/                # Mailer interface, SMTPMailer, NoopMailer
    │   ├── heartbeat/            # Periodic liveness log line
    │   ├── logger/               # Zerolog setup (JSON in prod, pretty in dev)
    │   ├── metrics/              # Prometheus middleware + /metrics handler
    │   ├── objectstore/          # S3-compatible storage interface + AWS implementation
    │   ├── pgdialect/            # pgx settings shared by every pool
    │   ├── pgtest/               # Postgres harness for integration-tagged tests
    │   ├── redis/                # Redis client wrapper
    │   ├── reqid/                # Request ID on the context
    │   ├── scopequery/           # Applies an authz scope to a list query
    │   ├── sessions/             # Session revocation shared across modules
    │   └── versioning/           # BuildInfo for /version endpoint
    ├── store/
    │   ├── repo/                 # Generic Repo[T] interface + GormRepo[T] implementation
    │   ├── expect.go             # ExpectError: keep an anticipated statement error out of the SQL log
    │   ├── like.go               # Escaped LIKE patterns for search input
    │   ├── query.go              # QueryOpts DSL: filters, WHERE clauses, sort, pagination, preloads
    │   └── tx.go                 # WithTx helper for database transactions
    ├── utils/
    │   ├── const/                # Shared constants (e.g. X-Request-ID header name)
    │   └── generate/             # UUID generation helpers
    └── worker/                   # Goroutine job pool: Enqueue, Start, Stop
```

---

## Package conventions

### `internal/api/<feature>/`

Each feature owns its slice of the API:

| File | Purpose |
|------|---------|
| `routes.go` | Registers Gin routes; constructs handler with its dependencies |
| `handler.go` | HTTP handlers: parse → call service/repo → respond |
| `transports.go` | Request and response structs (no logic) |
| `service.go` | Business logic (only for complex flows; omit for simple CRUD) |

### `internal/entities/<name>/`

One directory per entity. Only the GORM struct and `TableName()`. No methods, no business logic.

### `internal/platform/<name>/`

Infrastructure clients. Each package exposes a constructor and an interface — never import a platform package from `entities/` or `store/`.

### `internal/store/`

The `Repo[T]` generic interface is the **only** data-access abstraction. All handlers receive a `repo.Repo[MyEntity]` — no raw `*gorm.DB` inside handlers.

---

## Generic repository cheat-sheet

```go
import (
    "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store"
    "github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME/internal/store/repo"
)

r := repo.NewGormRepo[note.Note](db)

// Create
r.Create(ctx, &note.Note{...})

// Fetch by ID or UUID
r.GetByID(ctx, 42)
r.GetByUUID(ctx, uuid)

// Fetch one by filter
r.GetOne(ctx, store.QueryOpts{Filters: map[string]any{"email": "x@y.com"}})

// Paginated list with filter + sort
r.List(ctx, store.QueryOpts{
    Filters:  map[string]any{"user_id": userID},
    Sort:     []store.SortField{{Field: "created_at", Desc: true}},
    Page:     1,
    PageSize: 20,
})

// Partial update (no hooks)
r.UpdateColumnsByID(ctx, id, map[string]any{"status": "active"})

// Update only while a column still holds the expected value (compare-and-set)
r.UpdateColumnsGuarded(ctx, id, map[string]any{"status": "pending"}, nil, map[string]any{"status": "active"})

// Soft delete
r.SoftDelete(ctx, id)

// Transaction
store.WithTx(ctx, db, func(ctx context.Context, tx *gorm.DB) error {
    return r.Create(ctx, &note.Note{...}) // r joins the transaction through ctx
})
```

---

## Adding a new feature — checklist

1. `internal/entities/<feature>/` — GORM struct
2. `internal/platform/db/migrate.go` — new migration ID
3. `internal/api/<feature>/transports.go` — request/response types
4. `internal/api/<feature>/handler.go` — HTTP handlers
5. `internal/api/<feature>/routes.go` — wire routes
6. `internal/http/server/server.go` — call `<feature>.RegisterRoutes(...)`
7. `internal/platform/authz` — add the resource and an entry for every role, then gate each route with `RequirePermission`

If the feature needs emailing or background jobs:

8. `internal/api/<feature>/service.go` — business logic layer
9. Inject `email.Mailer` or `*worker.Worker` from `httpserver.Deps`
