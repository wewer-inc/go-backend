```
██╗    ██╗███████╗██╗    ██╗███████╗██████╗      ██████╗ ███████╗███████╗
██║    ██║██╔════╝██║    ██║██╔════╝██╔══██╗    ██╔═══██╗██╔════╝██╔════╝
██║ █╗ ██║█████╗  ██║ █╗ ██║█████╗  ██████╔╝    ██║   ██║███████╗███████╗
██║███╗██║██╔══╝  ██║███╗██║██╔══╝  ██╔══██╗    ██║   ██║╚════██║╚════██║
╚███╔███╔╝███████╗╚███╔███╔╝███████╗██║  ██║    ╚██████╔╝███████║███████║
 ╚══╝╚══╝ ╚══════╝ ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝     ╚═════╝ ╚══════╝╚══════╝

                The open engineering foundation by Wewer
```

> We believe strong systems should not start from scratch every time. This repository is Wewer's open engineering foundation for building clean, secure, production-minded software. It contains no client logic or proprietary business code — only the engineering patterns we trust and continue to refine in the open.

Built and maintained by [Wewer Technologies Inc.](https://wewer.io) — actively used in production, not abandoned.

---

## What this is

A production-grade Go backend starter that encodes Wewer's engineering standards: how we structure applications, handle authentication, manage configuration, log requests, expose metrics, enforce rate limits, run background jobs, and ship to production with Docker.

Clone it, run `make init`, and you have a working foundation in minutes — not days.

**This is opinionated.** It reflects the patterns that have worked across multiple Wewer products. It is not trying to be the right answer for every team. If the opinions fit, the foundation is yours.

## What this deliberately excludes

- Business logic of any kind
- Domain models beyond the `example` feature (which exists only to show the pattern)
- Frontend, GraphQL, gRPC, or anything outside a JSON REST API
- External job queues, service meshes, or distributed systems primitives

Contributors add patterns, not product.

---

## Quick start

```bash
make init                           # enter your GitHub org + app name — replaces all placeholders
cp .env.example .env                # fill in secrets
make docker-up DB_PROFILE=true      # starts api + postgres + redis
```

The API is live at `http://localhost:8080`.

```bash
curl http://localhost:8080/health   # liveness probe
curl http://localhost:8080/ready    # readiness probe (DB + Redis)
curl http://localhost:8080/version  # build info
```

---

## What's included

| Area                | What                                                        |
| ------------------- | ----------------------------------------------------------- |
| **Framework**       | Gin (HTTP), GORM (ORM), gormigrate (versioned migrations)   |
| **Auth**            | JWT access + refresh tokens, Google OAuth, bcrypt passwords |
| **Database**        | PostgreSQL with connection pooling, soft deletes            |
| **Cache**           | Redis — refresh token storage, GCRA rate limiting           |
| **Object storage**  | S3-compatible interface (AWS, MinIO, Cloudflare R2)         |
| **Email**           | SMTP interface — NoopMailer in dev, SMTPMailer in prod      |
| **Background jobs** | In-process goroutine worker pool with graceful drain        |
| **Observability**   | Zerolog structured logging, Prometheus metrics              |
| **Health checks**   | `/health` (liveness), `/ready` (DB + Redis probe)           |
| **Middleware**      | Request ID, logging, CORS, GCRA rate limiting, JWT auth     |
| **Config**          | Typed env vars with defaults, `.env` file support           |
| **Container**       | Multi-stage Docker build → distroless/nonroot runtime       |

---

## Project structure

```
.
├── cmd/server/          # Entry point — wires app, handles signals
├── internal/
│   ├── app/             # DI root — wires all platform clients and HTTP server
│   ├── api/
│   │   ├── auth/        # Auth service + handlers (register, login, refresh, Google OAuth)
│   │   └── example/     # Note CRUD — copy this for every new feature
│   ├── apierr/          # Typed API errors
│   ├── entities/        # Domain structs (no methods — plain data)
│   ├── http/
│   │   ├── middleware/  # Auth, request ID, logger, CORS, rate limit
│   │   └── server/      # Router wiring
│   ├── platform/
│   │   ├── auth/        # JWT sign + verify
│   │   ├── config/      # Env-based config loading
│   │   ├── db/          # GORM setup, migrations
│   │   ├── email/       # Mailer interface + SMTP/Noop implementations
│   │   ├── logger/      # Zerolog setup
│   │   ├── metrics/     # Prometheus middleware
│   │   ├── objectstore/ # S3 interface + AWS implementation
│   │   ├── redis/       # Redis client wrapper
│   │   └── versioning/  # Build info (ldflags-injected version, commit, date)
│   ├── store/
│   │   ├── repo/        # Generic Repo[T] — CRUD, list, upsert, transactions
│   │   └── query.go     # QueryOpts DSL (filters, sort, pagination, preloads)
│   ├── utils/           # Shared constants and helpers (headers, UUID generation)
│   └── worker/          # Goroutine job pool
├── ARCHITECTURE.md      # Layer model, design decisions, auth flow
├── CONTRIBUTING.md      # How to contribute
├── Dockerfile           # Multi-stage build → distroless runtime
├── docker-compose.yml   # api + postgres + redis
├── Makefile
└── .env.example
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for a full explanation of each layer and the reasoning behind each design decision.

---

## Adding a new feature

Copy the example feature as your starting point:

```bash
cp -r internal/api/example/ internal/api/myfeature/
```

Then:

1. Create your entity in `internal/entities/<feature>/`
2. Add a migration in `internal/platform/db/migrate.go`
3. Wire routes in `internal/http/server/server.go`

For flows that coordinate multiple repos, send email, or enqueue a job — add a `service.go` following `internal/api/auth/service.go`.

---

## Auth endpoints

| Method | Path                       | Auth |
| ------ | -------------------------- | ---- |
| POST   | `/v1/auth/register`        | —    |
| POST   | `/v1/auth/login`           | —    |
| POST   | `/v1/auth/refresh`         | —    |
| GET    | `/v1/auth/google`          | —    |
| GET    | `/v1/auth/google/callback` | —    |

All auth responses return:

```json
{
  "data": {
    "user": {
      "uuid": "...",
      "name": "...",
      "email": "...",
      "platform_role": "user"
    },
    "tokens": { "access_token": "...", "refresh_token": "..." }
  }
}
```

Pass `Authorization: Bearer <access_token>` on secured routes.

---

## Observability

| Endpoint       | Description                                  |
| -------------- | -------------------------------------------- |
| `GET /health`  | Always 200 — process is alive                |
| `GET /ready`   | 200 when DB + Redis reachable, 503 otherwise |
| `GET /metrics` | Prometheus text format                       |
| `GET /version` | Build info (version, commit, build time)     |

---

## Key environment variables

See `.env.example` for the full list.

```bash
APP_ENV=dev                  # dev | staging | prod
DB_DSN=postgres://...
REDIS_ADDR=redis:6379

JWT_SECRET=...               # Long random string — generate with: openssl rand -hex 32
JWT_ACCESS_EXPIRY=15m
JWT_REFRESH_EXPIRY=168h

GOOGLE_CLIENT_ID=...         # Leave empty to disable Google OAuth
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URL=https://api.example.com/v1/auth/google/callback

SMTP_HOST=...                # Leave empty → NoopMailer (logs emails to stdout)
CORS_ALLOWED_ORIGINS=https://app.example.com

S3_BUCKET=...                # Leave empty to disable object storage
```

---

## Make targets

```
make init          run once after cloning — replaces all placeholders
make setup         install pre-commit hooks
make run           run locally
make test          run tests with coverage
make build         compile binary
make lint          golangci-lint + staticcheck
make gosec         static security analysis
make docker-up     start api only
make docker-up DB_PROFILE=true    start api + postgres + redis
make docker-down
```

---

## Versioning roadmap

This repository follows semantic versioning. The path to v1.0 is community-driven — each version reflects real usage and discovered gaps.

| Version  | Focus                                           |
| -------- | ----------------------------------------------- |
| **v0.1** | Initial public foundation (current)             |
| **v0.2** | Improved Docker and local dev workflow          |
| **v0.3** | Observability and logging improvements          |
| **v0.4** | Auth and middleware hardening                   |
| **v1.0** | Production-ready baseline — community validated |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). For security issues, see [SECURITY.md](SECURITY.md).

---

## License

Copyright 2026 Wewer Technologies Inc. Licensed under the [Apache License 2.0](LICENSE).
