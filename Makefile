# -----------------------------------------
# Project Makefile — Go + Docker
# -----------------------------------------
# Usage:
#   make help
#   make run           # local run (no docker)
#   make docker-up     # run via docker compose
#   make docker-build  # build container image
#   make test          # run unit tests
#   make lint          # run linters (golangci-lint, staticcheck if installed)
# -----------------------------------------

# ====== Config ======
APP            ?= YOUR_APP_NAME
PKG            ?= ./...
MAIN           ?= ./cmd/server
BIN_DIR        ?= ./.bin
BUILD_DIR      ?= ./.build
COVER_DIR      ?= ./.coverage
COVERPKG       ?= ./internal/...
GO             ?= go

# Ensure local tools are on PATH
export PATH := $(CURDIR)/$(BIN_DIR):$(PATH)

# Docker image info
REGISTRY       ?=
IMAGE          ?= $(REGISTRY)$(if $(REGISTRY),/,)$(APP)
GIT_SHA        := $(shell git rev-parse --short HEAD 2>/dev/null || echo "nogit")
GIT_TAG        := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "0.0.0")
BUILD_DATE     := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
TAG            ?= $(GIT_TAG)-$(GIT_SHA)

# Build flags (inject version info)
LDFLAGS        := -s -w \
	-X main.version=$(GIT_TAG) \
	-X main.commit=$(GIT_SHA) \
	-X main.date=$(BUILD_DATE)

# Tools — always prefer local copies
GOLANGCI       ?= $(BIN_DIR)/golangci-lint
STATICCHECK    ?= $(BIN_DIR)/staticcheck
GOVULNCHECK    ?= $(BIN_DIR)/govulncheck
GITLEAKS       ?= $(shell command -v gitleaks 2>/dev/null)
GOSEC          ?= $(BIN_DIR)/gosec
GOSEC_FLAGS    ?= -severity medium -confidence medium

# Pinned tool versions — keep in sync with .github/workflows/ci.yml. Must
# support the Go toolchain in go.mod (older releases fail to build on newer Go).
GOLANGCI_VERSION ?= v2.12.2
STATICCHECK_VERSION ?= 2026.1
GOVULNCHECK_VERSION ?= v1.2.0
GOSEC_VERSION ?= v2.27.1
GREMLINS_VERSION ?= v0.6.0
MUTATE_PKGS ?= internal/platform/authz internal/platform/auth internal/http/middleware internal/http/middleware/ratelimit

# Docker/Compose
DOCKER         ?= docker
COMPOSE        ?= docker compose
PLATFORM       ?= linux/amd64
BUILD_ARGS     ?=
COMPOSE_PROJECT_NAME ?= YOUR_APP_NAME

# Env (optional .env)
ifneq (,$(wildcard .env))
	include .env
	export
endif

# Colors
YELLOW=\033[33m
GREEN=\033[32m
CYAN=\033[36m
BOLD=\033[1m
RESET=\033[0m

# Help macro
define HELP_LINE
	@printf "  $(BOLD)%-18s$(RESET) %s\n" "$(1)" "$(2)"
endef

.PHONY: init
init: ## Initialise a new project — replaces YOUR_GITHUB_ORG / YOUR_APP_NAME placeholders
	@if grep -rq "YOUR_GITHUB_ORG\|YOUR_APP_NAME" --include="*.go" --include="go.mod" . 2>/dev/null; then \
		printf "$(BOLD)Initialise boilerplate$(RESET)\n"; \
		printf "$(CYAN)GitHub org / username:$(RESET) "; read GITHUB_ORG; \
		printf "$(CYAN)App name (lowercase-hyphenated, e.g. my-saas):$(RESET) "; read APP_NAME; \
		if [ -z "$$GITHUB_ORG" ] || [ -z "$$APP_NAME" ]; then \
			printf "$(YELLOW)Aborted — both values are required.$(RESET)\n"; exit 1; \
		fi; \
		find . -type f \( \
			-name "*.go" -o -name "go.mod" -o -name "Makefile" -o \
			-name "Dockerfile" -o -name "*.yml" -o -name "*.yaml" -o \
			-name "*.md" -o -name ".env*" \
		\) -not -path "./.git/*" \
			-exec sed -i \
				-e "s|YOUR_GITHUB_ORG|$$GITHUB_ORG|g" \
				-e "s|YOUR_APP_NAME|$$APP_NAME|g" \
			{} \;; \
		printf "$(GREEN)✓ Replaced placeholders with org=$(BOLD)$$GITHUB_ORG$(RESET)$(GREEN) app=$(BOLD)$$APP_NAME$(RESET)\n"; \
		printf "$(CYAN)Next:$(RESET) cp .env.example .env  # then fill in secrets\n"; \
	else \
		printf "$(YELLOW)Placeholders already replaced — nothing to do.$(RESET)\n"; \
	fi

.PHONY: help
help:
	@printf "$(BOLD)Make targets$(RESET)\n"
	$(call HELP_LINE,init,Initialise project — replace placeholders with real org/app name)
	$(call HELP_LINE,setup,Install basic toolchain and git hooks)
	$(call HELP_LINE,hooks,Install git hooks (pre-commit))
	$(call HELP_LINE,tidy,Go mod tidy & vendor)
	$(call HELP_LINE,fmt,Format code (go fmt & goimports if present))
	$(call HELP_LINE,lint,Run linters (golangci-lint, staticcheck))
	$(call HELP_LINE,vuln,Run vulnerability scanner (govulncheck))
	$(call HELP_LINE,gosec,Run gosec static security scan)
	$(call HELP_LINE,gosec-report,Run gosec and write JSON to reports/gosec.json)
	$(call HELP_LINE,vet,Static checks built into Go (Catches common bugs))
	$(call HELP_LINE,test,Run unit tests with coverage)
	$(call HELP_LINE,cover,Open coverage report in terminal)
	$(call HELP_LINE,build,Build local binary)
	$(call HELP_LINE,run,Run app locally (no docker))
	$(call HELP_LINE,docker-up,Up via docker compose)
	$(call HELP_LINE,docker-down,Down via docker compose)
	$(call HELP_LINE,docker-prune, Prune dangling caches/volumes (global, safe-ish))
	$(call HELP_LINE,clean,Remove build artifacts & caches)
	@printf "\n$(CYAN)Image: $(IMAGE):$(TAG)$(RESET)\n"

# ========= Go Basics =========
.PHONY: setup
setup: ## Install basic dev deps (Local linting)
	@mkdir -p $(BIN_DIR)
	@if [ ! -x "$(BIN_DIR)/golangci-lint" ]; then \
	echo "$(YELLOW)> installing golangci-lint $(GOLANGCI_VERSION)$(RESET)"; \
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(GOLANGCI_VERSION)/install.sh | sh -s -- -b $(CURDIR)/$(BIN_DIR) $(GOLANGCI_VERSION); \
	fi
	@if [ ! -x "$(BIN_DIR)/staticcheck" ]; then \
		echo "$(YELLOW)> installing staticcheck $(STATICCHECK_VERSION)$(RESET)"; \
		GOBIN=$(CURDIR)/$(BIN_DIR) $(GO) install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION); \
	fi
	@if [ ! -x "$(BIN_DIR)/govulncheck" ]; then \
		echo "$(YELLOW)> installing govulncheck $(GOVULNCHECK_VERSION)$(RESET)"; \
		GOBIN=$(CURDIR)/$(BIN_DIR) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION); \
	fi
	@if [ ! -x "$(GOSEC)" ]; then \
		echo "$(YELLOW)> installing gosec $(GOSEC_VERSION)$(RESET)"; \
		curl -sSfL https://raw.githubusercontent.com/securego/gosec/$(GOSEC_VERSION)/install.sh | sh -s -- -b $(CURDIR)/$(BIN_DIR) $(GOSEC_VERSION); \
	fi
	@echo "$(GREEN)✓ setup complete$(RESET)"

.PHONY: hooks
hooks:
	@echo "Installing Git hooks..."
	@install -d .git/hooks
	@install -m 0755 scripts/pre-commit .git/hooks/pre-commit
	@echo "✓ pre-commit hook installed"

.PHONY: tidy
tidy: ## Run go mod tidy and vendor | Check for changes and update go.sum
	$(GO) mod tidy
	@if command -v go mod vendor >/dev/null 2>&1; then $(GO) mod vendor; fi

.PHONY: fmt
fmt: ## Format code (go fmt & goimports if present)
	$(GO) fmt $(PKG)
	@if command -v goimports >/dev/null 2>&1; then \
		find . -name '*.go' -not -path "./vendor/*" -print0 | xargs -0 goimports -w; \
	fi

.PHONY: vet
vet: ## Run go vet | Check for suspicious constructs 
	$(GO) vet $(PKG)

.PHONY: lint
lint: ## Run linters (golangci-lint, staticcheck, govulncheck, gitleaks) | Check for code quality issues
	@if [ -x "$(GOLANGCI)" ]; then "$(GOLANGCI)" run --timeout=5m ./...; else echo "$(YELLOW)golangci-lint not installed$(RESET)"; fi
	@if [ -x "$(STATICCHECK)" ]; then "$(STATICCHECK)" ./...; fi
	@if [ -n "$(GITLEAKS)" ]; then $(GITLEAKS) detect --no-git -s . || true; fi

.PHONY: vuln
vuln:
	@if [ -n "$(GOVULNCHECK)" ]; then $(GOVULNCHECK) ./... ; else echo "govulncheck not installed"; fi

.PHONY: gosec gosec-report
gosec: ## Run gosec static security scan
	@if [ ! -x "$(GOSEC)" ]; then echo "gosec not found. Run 'make setup'."; exit 1; fi
	@echo "→ gosec $(GOSEC_FLAGS)"
	@$(GOSEC) $(GOSEC_FLAGS) ./...

gosec-report: ## Run gosec and output JSON report
	@if [ ! -x "$(GOSEC)" ]; then echo "gosec not found. Run 'make setup'."; exit 1; fi
	@mkdir -p reports
	@echo "→ gosec (json) → reports/gosec.json"
	@$(GOSEC) $(GOSEC_FLAGS) -fmt=json -out=reports/gosec.json ./...


.PHONY: test
test: ## Run unit tests with coverage
	@mkdir -p $(COVER_DIR)
	@# -count=1 disables the test cache, matching CI: a cached profile can describe a tree
	@# that no longer exists, and a gate reading stale coverage passes code it never saw.
	$(GO) test $(PKG) -race -count=1 -covermode=atomic -coverpkg=$(COVERPKG) -coverprofile=$(COVER_DIR)/coverage.out

.PHONY: test-pg
test-pg: ## Run integration-tagged tests against real Postgres (needs TEST_DATABASE_URL)
	@if [ -z "$(TEST_DATABASE_URL)" ]; then \
		echo "$(YELLOW)set TEST_DATABASE_URL to a throwaway Postgres, e.g.$(RESET)"; \
		echo "  docker run -d --name pgtest -e POSTGRES_PASSWORD=pw -p 55433:5432 postgres:16-alpine"; \
		echo "  make test-pg TEST_DATABASE_URL='postgres://postgres:pw@localhost:55433/postgres?sslmode=disable'"; \
		exit 1; \
	fi
	@# -p 1: these suites share one database, so packages must not run in parallel.
	TEST_DATABASE_URL="$(TEST_DATABASE_URL)" $(GO) test -tags=integration -p 1 -count=1 $(PKG)

.PHONY: cover-gate
cover-gate: ## Fail if a package is under its coverage-floors.txt value | Needs 'make test' output
	@COVERAGE_ENFORCE=1 ./scripts/coverage-gate.sh $(COVER_DIR)/coverage.out

.PHONY: mutate
mutate: ## Run gremlins on the packages that guard security | Slow, so PR CI skips it
	@command -v gremlins >/dev/null || { echo "install: go install github.com/go-gremlins/gremlins/cmd/gremlins@$(GREMLINS_VERSION)"; exit 1; }
	@for p in $(MUTATE_PKGS); do \
		echo "> gremlins: $$p"; \
		( cd $$p && gremlins unleash . ) || exit 1; \
	done

.PHONY: cover
cover: ## Show coverage report in terminal | Requires 'make test' first
	@if [ -f $(COVER_DIR)/coverage.out ]; then \
		$(GO) tool cover -func=$(COVER_DIR)/coverage.out; \
	else \
		echo "$(YELLOW)No coverage file. Run 'make test' first.$(RESET)"; \
	fi

.PHONY: build
## Build the application
build: tidy fmt vet lint
	@mkdir -p $(BUILD_DIR)
	$(GO) build -ldflags '$(LDFLAGS)' -o $(BUILD_DIR)/$(APP) $(MAIN)
	@echo "$(GREEN)✓ built $(BUILD_DIR)/$(APP)$(RESET)"

.PHONY: run
run: ## Run the application
	$(GO) run -ldflags '$(LDFLAGS)' $(MAIN)


# ====== Docker workflow ======
# ====== Docker / Compose targets ======
export COMPOSE_PROJECT_NAME ?= $(COMPOSE_PROJECT_NAME)  # ensure compose picks it up

.PHONY: docker-up
docker-up: ## Up via compose (starts api + postgres + redis)
	$(COMPOSE) up --build -d
	$(COMPOSE) ps


.PHONY: docker-down
docker-down: ## Down via compose
	$(COMPOSE) down

.PHONY: docker-clean
docker-clean: ## Stop & remove containers, images (local), and volumes for this project
	@echo ">> compose down (containers, volumes, local images, orphans)"
	$(COMPOSE) down -v --rmi local --remove-orphans
	@echo ">> remove explicitly tagged image (ignore errors if missing)"
	-$(DOCKER) rmi $(IMAGE):$(TAG) 2>/dev/null || true
	@echo ">> remove project-prefixed volumes (e.g., $(COMPOSE_PROJECT_NAME)_*)"
	-$(DOCKER) volume rm $$($(DOCKER) volume ls -q --filter "name=^$(COMPOSE_PROJECT_NAME)_") 2>/dev/null || true
	@echo ">> done"

.PHONY: docker-prune
docker-prune: ## Prune dangling caches/volumes (global, safe-ish)
	-$(DOCKER) system prune -f
	-$(DOCKER) volume prune -f
	-$(DOCKER) builder prune -f

# ====== Cleanup ======
.PHONY: clean
clean: ## Remove build artifacts & caches
	rm -rf $(BUILD_DIR) $(COVER_DIR)
	@echo "$(GREEN)✓ cleaned$(RESET)"