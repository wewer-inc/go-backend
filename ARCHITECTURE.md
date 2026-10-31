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
│  RequestID → Logger → Body checks → Metrics → CORS →    │
│  RateLimit → Auth → Permission gate                     │
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
| `auditlog`    | Hash-chained audit recorder and verifier      |
| `auth`        | JWT sign and verify, opaque tokens, password policy |
| `authz`       | The access policy: pure functions, no I/O     |
| `config`      | Typed env var loading                         |
| `crypto`      | AES-GCM for secrets at rest                   |
| `db`          | GORM setup, connection pool, migration runner |
| `dbstats`     | Query count and time for the request log      |
| `email`       | Mailer interface; SMTP in prod, Noop in dev   |
| `heartbeat`   | Periodic liveness log line                    |
| `logger`      | Zerolog setup (JSON in prod, pretty in dev)   |
| `metrics`     | Prometheus middleware and `/metrics` handler  |
| `pgdialect`   | pgx settings shared by every pool             |
| `pgtest`      | Postgres harness for integration tests        |
| `redis`       | Redis client wrapper                          |
| `reqid`       | Request ID on the context                     |
| `scopequery`  | Applies an `authz` scope to a list query      |
| `sessions`    | Session revocation shared across modules      |
| `versioning`  | Build info injected at compile time           |

Platform packages have no knowledge of feature logic. They are pure clients.

### `internal/http`

#### Middleware stack (applied in this order)

1. `gin.Recovery()` — panic recovery, returns 500
2. `RequestIDMiddleware()` — assigns `X-Request-ID` to every request
3. `Logger()` — structured request log at completion
4. `SecurityHeaders()` — response hardening headers
5. `BodyLimit()` — 413 on an oversize body before it is read
6. `RejectNULBytes()` — 400 on a NUL byte, which Postgres text cannot store
7. `metrics.Middleware()` — Prometheus histogram per route
8. `cors.New()` — CORS from config
9. `UserAuth` / `AdminAuth` — JWT verification and session check (per group)
10. `ratelimit.Global()` / `Admin()` — GCRA token bucket, Redis-backed (optional), after auth so it is keyed by user
11. `RequirePermission` / `RequireCapability` — the policy decision (per route)

Order matters: request ID must come before logger so the ID appears in the log line. A middleware that rejects must abort, because returning alone lets the chain continue.

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

    A retired token presented again:
    ├─ the previous generation, within REFRESH_RACE_WINDOW: a concurrent request lost.
    │  409 refresh_retry, session kept
    └─ anything else: a replay. The session is revoked

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

## Authorization

`internal/platform/authz` holds the whole policy as pure functions over a role, a resource and a row scope. Anything it does not recognise is denied. Keeping it free of I/O lets the tests walk every role and resource combination.

```
Route gate:   middleware.RequirePermission(authz.ResNote, authz.ActionRead)   the role may read notes at all
Single row:   authz.Decide(subject, resource, action, ref)                    this actor may read this row
List:         scopequery.ForOwned(subject, resource, ownerColumn)             only rows in reach come back
```

The subject is built from the database row on every request, so a role change applies at once and a claim in a token is never trusted. A row out of reach answers 404 rather than 403, so the API does not confirm it exists. Clients read their own permissions from `GET /v1/auth/permissions`.

Rare, sensitive operations such as role changes and "login as" are capabilities rather than matrix cells. The escalation guard stops anyone granting a role that holds a write permission or capability they lack themselves.

## Audit Trail

`internal/platform/auditlog` appends a row for each security-relevant change. Each row's hash covers the previous row's hash, so editing or removing a row in the middle breaks the chain, and `GET /v1/admin/audit/verify` reports where. Appends take a Postgres advisory lock because two concurrent writers would otherwise fork the chain. That lock is why routine denials go to logs and metrics instead. Sensitive keys are redacted before a row is written.

## Data Layer Safeguards

- **pgx exec mode:** `pgdialect` pins `QueryExecModeExec`, so adding a column cannot leave pooled connections holding a stale cached plan and failing with 500s.
- **SQL logs:** parameter values stay out of slow and failed query logs unless `DB_LOG_QUERY_VALUES` is on.
- **Compare-and-set:** `UpdateColumnsGuarded` updates a row only while named columns still hold expected values. Session rotation depends on this.
- **Search input:** `store.LikeContains` and `store.LikeEscape` make `%` and `_` match literally.

## Migrations and Rollouts

Migrations live in `internal/platform/db/migrate.go` and never change once shipped. They run at startup when `DB_MIGRATE_ON_START=true`, or on their own through the binary's `migrate` subcommand, which is how the deploy workflow applies them before rolling out. The old revision keeps serving against the migrated schema during a rollout or rollback, so a deploy may only add. Drop or rename in a later deploy.

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
