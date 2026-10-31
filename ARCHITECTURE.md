# Architecture

This document explains the structural decisions behind this boilerplate — not what the code does (the code does that), but why it is organized this way.

---

## Layer Model

```
HTTP Request
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  Middleware Stack                                        │
│  RequestID → Logger → Metrics → CORS → RateLimit → Auth │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
              ┌─────────────────┐
              │    Handler      │  ← validates input, calls service or repo
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │    Service      │  ← optional; for multi-repo or side-effect flows
              └────────┬────────┘
                       │
         ┌─────────────┼──────────────┐
         ▼             ▼              ▼
    Repo[T]         Mailer         Worker
    (DB)            (SMTP)      (background jobs)

```

Each layer has a single responsibility and depends only downward. Handlers never touch the database directly; repos never know about HTTP.

---

## Layers in Detail

### `cmd/server`

Entry point only. Reads build flags, calls `app.Build()`, starts the server, listens for OS signals, and calls graceful shutdown. No business logic lives here.

### `internal/app`

Dependency injection root. `app.Build()` wires every platform client (DB, Redis, S3, email, worker) and passes them as explicit structs to the HTTP server. There is no DI framework — plain Go structs and constructor functions are sufficient and easier to follow.

### `internal/api/<feature>`

One directory per product feature. Each contains:

```
routes.go       — registers routes and injects dependencies
handler.go      — HTTP handlers (validate → call → respond)
transports.go   — request and response types
service.go      — optional; only add when a handler needs to coordinate
                  multiple repos, send email, or enqueue a job
```

`internal/api/example/` is a working copy-paste template. When adding a feature, copy it and rename.

### `internal/entities`

Plain Go structs with no methods. They represent database rows. No business logic belongs here — keep entities as dumb data containers so they can be shared freely between layers without creating circular imports.

### `internal/store`

#### `Repo[T any]`

A generic CRUD interface backed by GORM. Every entity gets its own repo instantiated with `repo.NewGormRepo[T](db)`. This covers the common 90% of data access:

```go
userRepo := repo.NewGormRepo[user.User](db)
u, err := userRepo.GetByUUID(ctx, uuid)
```

When you need something the generic repo cannot express (a join, a raw aggregation, a CTE), write a dedicated function directly against `*gorm.DB`. Do not expand the `Repo[T]` interface for one-off queries.

#### `QueryOpts`

A struct-based DSL for filtering, sorting, pagination, and eager loading. Keeps query construction out of handlers:

```go
opts := store.QueryOpts{
    Filters:  map[string]any{"user_id": userID},
    Where:    []store.Clause{{Expr: "created_at > ?", Args: []any{since}}},
    Sort:     []store.SortField{{Field: "created_at", Desc: true}},
    Page:     1,
    PageSize: 20,
    Preloads: []string{"Tags"},
}
notes, pageInfo, err := noteRepo.List(ctx, opts)
```

### `internal/platform`

Infrastructure clients. Each sub-package owns one external concern:

| Package       | Responsibility                                |
| ------------- | --------------------------------------------- |
| `auth`        | JWT sign and verify                           |
| `config`      | Typed env var loading                         |
| `db`          | GORM setup, connection pool, migration runner |
| `email`       | Mailer interface; SMTP in prod, Noop in dev   |
| `logger`      | Zerolog setup (JSON in prod, pretty in dev)   |
| `metrics`     | Prometheus middleware and `/metrics` handler  |
| `redis`       | Redis client wrapper                          |
| `versioning`  | Build info injected at compile time           |

Platform packages have no knowledge of feature logic. They are pure clients.

### `internal/http`

#### Middleware stack (applied in this order)

1. `gin.Recovery()` — panic recovery, returns 500
2. `RequestIDMiddleware()` — assigns `X-Request-ID` to every request
3. `Logger()` — structured request log at completion
4. `metrics.Middleware()` — Prometheus histogram per route
5. `cors.New()` — CORS from config
6. `ratelimit.Global()` — GCRA token bucket, Redis-backed (optional)
7. `UserAuth` / `AdminAuth` — JWT verification, role enforcement (per-route)

Order matters: request ID must come before logger so the ID appears in the log line.

#### `internal/http/server`

Router creation and route wiring only. No business logic. If wiring a new feature, add its `routes.RegisterRoutes(rg, deps)` call here.

### `internal/worker`

An in-process goroutine pool. Use it for fire-and-forget side effects that should not block the HTTP response: sending a welcome email after registration, post-processing an upload.

**What it is not:** a distributed job queue. If a job must survive a process restart, use an external queue (Temporal, asynq, SQS). The worker pool is intentionally simple — adding persistence would be a new dependency that not every project needs.

---

## Auth Flow

```
POST /v1/auth/login
    │
    ├─ verify password (bcrypt)
    ├─ create a row in sessions, holding only the SHA-256 of an opaque refresh token
    ├─ issue access token (JWT, 15m, signed with JWT_SECRET, carrying the session's id as sid)
    └─ return { access_token, refresh_token }

POST /v1/auth/refresh
    ├─ find the session by the token's hash
    ├─ rotate with a compare-and-set on that hash, remembering the previous one
    └─ return { access_token, refresh_token }

    The previous token presented again:
    ├─ within REFRESH_RACE_WINDOW: a concurrent request lost. 409 refresh_retry, session kept
    └─ later: a replay. The session is revoked

Authenticated request:
    Authorization: Bearer <access_token>
    │
    └─ UserAuth middleware:
        ├─ parse and verify JWT
        ├─ check the jti denylist, if Redis is enabled
        ├─ load user from DB (ensures account not deleted mid-session)
        ├─ load the session from DB (a revoked session stops working on the next request)
        └─ store actor_user_id, actor_user_uuid, actor_platform_role in Gin context
```

Sessions live in Postgres, so revoking one takes effect on the next request and auth works with Redis disabled. Redis adds rate limiting and the access-token denylist.

---

## Design Decisions

**Gin over Echo or Fiber**
Gin has the largest ecosystem, the most middleware libraries, and the most Stack Overflow answers. For a boilerplate used across varied projects, familiarity matters more than marginal performance differences.

**GORM over sqlc or pgx directly**
GORM's migration support (via gormigrate), soft-delete handling, and association loading cover the majority of CRUD without boilerplate. Projects that need raw query control can always escape to `db.Raw()` — the generic repo does not prevent this.

**In-process worker over external queue**
Most applications do not need durable, distributed job execution on day one. The goroutine pool adds zero infrastructure dependencies while covering the common cases. Projects that grow to need persistence can add asynq or Temporal as a platform package without restructuring the rest of the codebase.

**gormigrate over golang-migrate**
gormigrate keeps migrations in Go code alongside the models they create. No separate SQL files to maintain, no migration runner binary to install, and migrations run automatically on startup when `DB_MIGRATE_ON_START=true`.

**Distroless container image**
The final Docker image contains only the statically compiled Go binary and CA certificates — no shell, no package manager, no attack surface. `nonroot` user is set in the image so the process never runs as root.
