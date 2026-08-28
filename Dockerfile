# ---- Build stage ----
FROM golang:1.27.0 AS builder
WORKDIR /src

# Reproducible, static builds
ENV CGO_ENABLED=0 GO111MODULE=on

# Accept build metadata from the outside world
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

# Makefile already uses GIT_TAG / GIT_SHA / BUILD_DATE → provide them
ENV GIT_TAG=${VERSION} \
    GIT_SHA=${COMMIT} \
    BUILD_DATE=${DATE}

# Cache deps
COPY go.mod go.sum ./
RUN go mod download

# Copy source (.git, .env and local cruft are excluded via .dockerignore)
COPY . .

# Build binary directly — avoids pulling in lint/fmt/tidy deps not present in CI image
RUN mkdir -p .build && \
    go build \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o .build/YOUR_APP_NAME \
      ./cmd/server

# ---- Runtime stage ----
FROM gcr.io/distroless/static:nonroot

# Re-declare build args in this stage so the labels below can reference them.
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

# OCI image metadata (https://github.com/opencontainers/image-spec)
LABEL org.opencontainers.image.title="YOUR_APP_NAME" \
      org.opencontainers.image.source="https://github.com/YOUR_GITHUB_ORG/YOUR_APP_NAME" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}"

WORKDIR /app
COPY --from=builder /src/.build/YOUR_APP_NAME /app/YOUR_APP_NAME
EXPOSE 8080
USER nonroot:nonroot

# Self-probe via the binary's -healthcheck flag (image has no shell/wget/curl).
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/YOUR_APP_NAME", "-healthcheck"]

ENTRYPOINT ["/app/YOUR_APP_NAME"]