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
| **Sign-in**         | Short-lived JWTs over Postgres-backed sessions, single-use refresh tokens, Google OAuth, bcrypt, TOTP two-factor, account lockout |
| **Access control**  | Deny-by-default role matrix, row scoping, capabilities and an escalation guard, all in one pure package |
| **Audit trail**     | Append-only, hash-chained log of security-relevant changes, with a verify endpoint |
| **Database**        | PostgreSQL with connection pooling, soft deletes            |
| **Cache**           | Redis (optional) — GCRA rate limiting, access token denylist |
| **Object storage**  | S3-compatible interface (AWS, MinIO, Cloudflare R2)         |
| **Email**           | SMTP interface — NoopMailer in dev, SMTPMailer in prod      |
| **Background jobs** | In-process goroutine worker pool with graceful drain        |
| **Observability**   | Zerolog structured logging, Prometheus metrics              |
| **Health checks**   | `/health` (liveness), `/ready` (DB + Redis probe)           |
| **Middleware**      | Request ID, logging, security headers, body size limit, NUL rejection, CORS, GCRA rate limiting, JWT auth |
| **Quality gates**   | Per-package coverage floors, Postgres integration suite, weekly mutation testing, gitleaks, govulncheck |
| **Config**          | Typed env vars with defaults, `.env` file support           |
| **Container**       | Multi-stage Docker build → distroless/nonroot runtime       |
| **Deployment**      | Optional GitHub Actions workflow for ECS Fargate over OIDC, with a `migrate` step before rollout |

---

## Project structure

```
.
├── cmd/server/          # Entry point — wires app, handles signals
├── internal/
│   ├── app/             # DI root — wires all platform clients and HTTP server
│   ├── api/
│   │   ├── adminaudit/  # Read and verify the audit trail
│   │   ├── auth/        # Sign-in, sessions, passwords, two-factor, "login as"
│   │   ├── common/      # Response envelope and request binding
│   │   ├── example/     # Note CRUD — copy this for every new feature
│   │   └── users/       # Admin role changes
│   ├── apierr/          # Typed API errors
│   ├── entities/        # Domain structs (plain data)
│   ├── http/
│   │   ├── middleware/  # Auth, permission gates, request ID, logger, body checks, rate limit
│   │   └── server/      # Router wiring
│   ├── platform/
│   │   ├── auditlog/    # Hash-chained audit recorder and verifier
│   │   ├── auth/        # JWT sign + verify, opaque tokens, password policy
│   │   ├── authz/       # Roles, permissions, scope and capabilities. No I/O
│   │   ├── config/      # Env-based config loading
│   │   ├── crypto/      # AES-GCM for secrets at rest
│   │   ├── db/          # GORM setup, migrations, SQL log redaction
│   │   ├── dbstats/     # Per-request query count and time
│   │   ├── email/       # Mailer interface + SMTP/Noop implementations
│   │   ├── heartbeat/   # Periodic liveness log line with pool counters
│   │   ├── logger/      # Zerolog setup
│   │   ├── metrics/     # Prometheus middleware
│   │   ├── objectstore/ # S3 interface + AWS implementation
│   │   ├── pgdialect/   # pgx connection settings every pool shares
│   │   ├── pgtest/      # Postgres harness for integration-tagged tests
│   │   ├── redis/       # Redis client wrapper
│   │   ├── reqid/       # Request ID on the context
│   │   ├── scopequery/  # Turns an authz scope into list query clauses
│   │   ├── sessions/    # Session revocation shared across modules
│   │   └── versioning/  # Build info (ldflags-injected version, commit, date)
│   ├── store/
│   │   ├── repo/        # Generic Repo[T] — CRUD, list, upsert, transactions
│   │   └── query.go     # QueryOpts DSL (filters, sort, pagination, preloads)
│   ├── utils/           # Shared constants and helpers (headers, UUID generation)
│   └── worker/          # Goroutine job pool
├── deploy/              # ECS task definition template
├── scripts/             # Coverage gate
├── ARCHITECTURE.md      # Layer model, design decisions, auth flow
├── CONTRIBUTING.md      # How to contribute
├── Dockerfile           # Multi-stage build → distroless runtime
├── docker-compose.yml   # api + postgres + redis
├── coverage-floors.txt  # Minimum coverage per package
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
4. Add the resource to `internal/platform/authz` and gate each route with `RequirePermission`; the policy tests fail until every role has an entry

For flows that coordinate multiple repos, send email, or enqueue a job — add a `service.go` following `internal/api/auth/service.go`.

---

## Auth endpoints

| Verb   | Route                      | Needs  |
| :----- | :------------------------- | :----- |
| POST   | `/v1/auth/register`        | —      |
| POST   | `/v1/auth/login`           | —      |
| POST   | `/v1/auth/refresh`         | —      |
| POST   | `/v1/auth/forgot-password` | —      |
| POST   | `/v1/auth/reset-password`  | —      |
| POST   | `/v1/auth/mfa/verify`      | —      |
| GET    | `/v1/auth/google`          | —      |
| GET    | `/v1/auth/google/callback` | —      |
| POST   | `/v1/auth/logout`          | Bearer |
| POST   | `/v1/auth/change-password` | Bearer |
| GET    | `/v1/auth/permissions`     | Bearer |
| GET    | `/v1/auth/sessions`        | Bearer |
| DELETE | `/v1/auth/sessions`        | Bearer |
| DELETE | `/v1/auth/sessions/:sid`   | Bearer |
| POST   | `/v1/auth/mfa/enroll/start` | Bearer |
| POST   | `/v1/auth/mfa/enroll/confirm` | Bearer |
| GET    | `/v1/auth/mfa/status`      | Bearer |
| POST   | `/v1/auth/mfa/backup-codes/regenerate` | Bearer |
| POST   | `/v1/auth/impersonate/end` | Bearer |

`DELETE /v1/auth/sessions` signs out every session but the current one.

Refresh tokens rotate on every use. If several requests refresh with the same token at once, one succeeds and the others get `409 refresh_retry`: keep the session, and retry with the newest token. Presenting the previous token after `REFRESH_RACE_WINDOW`, or any older one at any time, is treated as theft and revokes the session.

Passwords must be 12 characters to 72 bytes, with no composition rules, and differ from the last `PASSWORD_HISTORY_COUNT`. Repeated failed sign-ins lock an address for `AUTH_LOCKOUT_WINDOW`. `forgot-password` answers the same for every well-formed address and does all its work on the worker, so neither the response nor its timing reveals whether an account exists. Set `PASSWORD_RESET_URL` or no reset email is sent.

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

On an account with two-factor authentication on, `login` and the Google callback answer with `{"status": "mfa_required", "mfa_token": "...", "expires_at": "..."}` instead of tokens. Post the token with a TOTP or backup code to `/v1/auth/mfa/verify` to get the usual response. Each TOTP code works once. Turning MFA on requires `MFA_ENCRYPTION_KEY`, and it and regenerating backup codes both require `current_password`. An account with no password, which signs in with Google, must have signed in within the last 5 minutes instead, or gets `403 reauthentication_required`. Both changes email the user.

## Admin routes

Every route below needs an admin token and passes through one more check.

| Verb   | Route                  | Additional check            |
| :----- | :--------------------- | :-------------------------- |
| GET    | `/v1/admin/audit`      | `admin.audit:read`          |
| GET    | `/v1/admin/audit/verify` | `admin.audit:read`        |
| POST   | `/v1/admin/users/:uuid/mfa/reset` | capability `admin.users.mfa:reset`, plus the admin's own TOTP code |
| POST   | `/v1/admin/users/:uuid/impersonate` | capability `admin.users:impersonate` |
| PATCH  | `/v1/admin/users/:uuid/role` | capability `admin.users.role:update` |

A role change signs the target out everywhere and is audited. The last admin cannot be demoted.

"Login as" issues a five-minute access token with no refresh token. It cannot nest, cannot target an admin or yourself, and cannot change the account's password, MFA or other sessions. Every audit row written inside it names the impersonator, and the user's session list labels it.

The audit trail is a hash chain (`internal/platform/auditlog`). On its own it cannot detect tail truncation: deleting the newest rows, or all of them, leaves a valid shorter chain, and the hash is unkeyed, so someone able to rewrite the table can recompute it. To detect those, store `head_id` and `head` from `/verify` somewhere the database's writers cannot modify, and pass them back as `?checkpoint_id=&checkpoint_hash=`. Nothing here exports them for you.

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

MFA_ENCRYPTION_KEY=...       # Required to turn on two-factor. Generate with: openssl rand -hex 32
PASSWORD_RESET_URL=https://app.example.com/reset-password   # Leave empty and no reset email is sent
DB_LOG_QUERY_VALUES=false    # Keep false wherever real personal data exists
```

With Redis off, sign-in still works but nothing rate limits it. Only account lockout remains.

---

## Make targets

```
make init          run once after cloning — replaces all placeholders
make setup         install pre-commit hooks
make run           run locally
make test          run tests with coverage
make cover-gate    check coverage-floors.txt (run make test first)
make test-pg       integration tests, needs TEST_DATABASE_URL
make mutate        mutation tests on the security packages (slow)
make build         compile binary
make lint          golangci-lint, staticcheck, gitleaks
make gosec         static security analysis
make vuln          govulncheck only
make docker-up     start api only
make docker-up DB_PROFILE=true    start api + postgres + redis
make docker-down
```

---

## CI and deployment

`.github/workflows/ci.yml` runs on pull requests and on pushes to `main`, `staging` and `dev`. Lint, static analysis, secret scanning, unit tests with the coverage gate, and the Postgres suite run as separate jobs. Require the single **Lint, Test, Scan** check in branch protection, because it fails if any of them does.

`.github/workflows/deploy.yml` builds an image, runs the `migrate` subcommand, then rolls out to ECS Fargate in one region. It is skipped until the `DEPLOY_ROLE_ARN` variable is set, so a new project does not fail on it. Before first use, add your secrets to `deploy/taskdef.json`; it lists only the two required ones. Migrations run before the new code, so a deploy may only add to the schema.

## Upgrading an earlier copy

These changes affect anything built from an older version of this template:

- Sessions moved to Postgres, so every user must sign in again.
- Clients must handle the `mfa_required` sign-in response, `409 refresh_retry` on refresh, and `current_password` on sensitive changes.
- New passwords need at least 12 characters.
- A list can now skip its count query when a short page already proves the total.
- A custom `Repo[T]` implementation must add `UpdateColumnsGuarded`.

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
