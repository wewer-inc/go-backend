# Package & Folder Guide

Short, opinionated conventions for naming and structuring packages in this boilerplate.

---

## Folder layout

```
.
├── cmd/server/                   # Binary entry point. Wires app.Build() + signal handling. No logic.
└── internal/
    ├── api/
    │   ├── auth/                 # Auth feature: service + handlers + routes + transports
    │   ├── common/               # Shared response envelope: Response[T]
    │   └── example/              # Example Note CRUD — copy-paste template for new features
    ├── apierr/                   # Typed API errors with HTTP status codes
    ├── app/                      # Dependency injection root: app.Build() wires everything
    ├── entities/
    │   ├── role.go               # Typed Role constants (RoleUser, RoleAdmin, RoleSupport)
    │   ├── user/                 # User entity
    │   └── note/                 # Example entity
    ├── http/
    │   ├── middleware/           # Request ID, logger, auth (UserAuth/AdminAuth), CORS
    │   │   └── ratelimit/        # GCRA rate limiter middleware backed by Redis
    │   └── server/               # NewRouter: wires all middleware and feature routes
    ├── platform/
    │   ├── auth/                 # JWT verifier + issuer (token sign/verify)
    │   ├── config/               # Config struct loaded from environment variables
    │   ├── db/                   # GORM + PostgreSQL setup, migration runner
    │   ├── email/                # Mailer interface, SMTPMailer, NoopMailer
    │   ├── logger/               # Zerolog setup (JSON in prod, pretty in dev)
    │   ├── metrics/              # Prometheus middleware + /metrics handler
    │   ├── objectstore/          # S3-compatible storage interface + AWS implementation
    │   ├── redis/                # Redis client wrapper
    │   └── versioning/           # BuildInfo for /version endpoint
    ├── store/
    │   ├── repo/                 # Generic Repo[T] interface + GormRepo[T] implementation
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

// Soft delete
r.SoftDelete(ctx, id)

// Transaction
store.WithTx(ctx, db, func(tx *gorm.DB) error {
    txRepo := repo.NewGormRepo[note.Note](tx)
    return txRepo.Create(ctx, &note.Note{...})
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

If the feature needs emailing or background jobs:

7. `internal/api/<feature>/service.go` — business logic layer
8. Inject `email.Mailer` or `*worker.Worker` from `httpserver.Deps`
