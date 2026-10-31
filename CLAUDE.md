# CLAUDE.md

Guidance for Claude Code when working in this repository. A Go (Gin + GORM) JSON REST
modular monolith over PostgreSQL, shipped as a distroless nonroot container.

Read first: `ARCHITECTURE.md` (layers and why), `PACKAGES.md` (folder conventions and adding a
module), `CONTRIBUTING.md` (rules every module must honor).

## Commands

```bash
make run             # start the API on this machine
make test            # unit tests, race detector on, writes .coverage
make cover-gate      # fail if a package is under its coverage-floors.txt value; needs make test first
make test-pg TEST_DATABASE_URL=...   # tests tagged integration, against a real Postgres
make lint            # golangci-lint, staticcheck, gitleaks
make vuln            # govulncheck
make gosec           # gosec on its own
make mutate          # gremlins on the security packages; slow, also runs weekly in CI
```

`make init` is a one-time placeholder rename for a new project. It is unrelated to Claude's `/init`.

## Non-obvious rules

- **Layering:** middleware, then handler, then optional service, then `Repo[T]`. Handlers never touch
  `*gorm.DB`, and repos know nothing about HTTP.
- **Authorization:** decisions read `middleware.GetActorSubject`, built from the database on each
  request. Never read a role from token claims. Gate routes with `RequirePermission` or
  `RequireCapability`, single rows with `authz.Decide`, and lists with `scopequery`.
- **Middleware chains:** a Gin middleware that rejects must abort. Returning does not stop the chain,
  and a middleware that calls `c.Next()` runs everything after it before it returns.
- **Migrations:** Go code in `internal/platform/db/migrate.go`, never edited once shipped, and
  backward-compatible: a deploy may only add. Drop or rename in a later deploy.
- **Audit log:** record security-relevant changes through `auditlog`. Sensitive values never go in
  `Detail`. Appends take a Postgres advisory lock, so routine denials go to logs and metrics instead.
- **Errors:** respond with `apierr` values and wrap internal failures with `apierr.InternalErr`, so the
  cause reaches the logs by `request_id` and never the client.
- **Worker:** best-effort and in-process. It drops jobs when full and survives no restart.
