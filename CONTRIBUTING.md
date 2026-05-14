# Contributing to Wewer Go Backend Boilerplate

Thank you for your interest in contributing. This repository is Wewer's open engineering foundation — we welcome improvements to patterns, tooling, documentation, and standards. We do not accept product or business logic.

---

## What belongs here

**In scope:**
- Improvements to existing patterns (auth, middleware, error handling, config, logging, observability)
- New platform integrations that are commonly needed (e.g., a new storage backend, a new email provider)
- Developer experience improvements (Makefile targets, Docker workflow, pre-commit hooks)
- Documentation and architecture clarity
- Bug fixes in the boilerplate code itself
- Test coverage for existing patterns

**Out of scope:**
- Business logic specific to any product or domain
- Opinionated choices that benefit only one use case at the cost of others
- New dependencies without strong justification (this is a foundation — every dependency is inherited by downstream projects)

If you are unsure, open an issue and discuss before writing code.

---

## Getting started

```bash
# 1. Fork the repository on GitHub, then clone your fork
git clone https://github.com/<your-org>/go-backend.git
cd go-backend

# 2. Install pre-commit hooks
make setup

# 3. Copy the env template and start the stack
cp .env.example .env
make docker-up DB_PROFILE=true

# 4. Run the tests
make test
```

The pre-commit hook runs `fmt → vet → lint → gosec → test` before every commit. CI runs the same checks on every PR.

---

## Branch naming

| Prefix | Use |
|--------|-----|
| `feat/` | New pattern or capability |
| `fix/` | Bug fix |
| `docs/` | Documentation only |
| `refactor/` | Code restructuring without behavior change |
| `chore/` | Tooling, CI, dependency updates |

Examples: `feat/add-nats-platform`, `fix/rate-limit-burst-config`, `docs/improve-architecture-overview`

---

## Making a pull request

1. Keep PRs focused. One logical change per PR.
2. Run `make lint` and `make test` locally before pushing — CI will reject failures.
3. If you are adding a new platform package, include a brief doc comment on the package and an example in the PR description.
4. Fill out the PR template. The checklist is there to protect reviewers' time, not yours.
5. PRs that add new dependencies must explain: what problem it solves, why an existing dependency cannot solve it, and the dependency's license.

---

## Code style

- Follow standard Go formatting — `gofmt` is enforced by the pre-commit hook.
- No comments that explain *what* the code does. Comments are for *why*: hidden constraints, invariants, workarounds.
- No multi-line comment blocks or docstrings on simple functions.
- Error strings are lowercase, no punctuation at the end (Go convention).
- Keep the generic `Repo[T]` interface stable. One-off query needs do not warrant new interface methods — use `*gorm.DB` directly.

---

## Commit messages

Use the imperative mood, present tense:

```
add NATS platform client
fix rate limit burst not applying from config
update ARCHITECTURE.md with worker pool scope
```

No ticket references or issue numbers in commit messages — those belong in the PR description.

---

## Reporting issues

Use the GitHub issue templates:
- **Bug report** — something broken in the boilerplate itself
- **Feature request** — a pattern or capability worth adding

For security issues, do **not** open a public issue. See [SECURITY.md](SECURITY.md).

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.
