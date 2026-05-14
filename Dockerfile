# ---- Build stage ----
FROM golang:1.26.3 AS builder
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

# Copy source (you can keep .git ignored via .dockerignore)
COPY . .

# Build binary directly — avoids pulling in lint/fmt/tidy deps not present in CI image
RUN mkdir -p .build && \
    go build \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o .build/YOUR_APP_NAME \
      ./cmd/server

# ---- Runtime stage ----
FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=builder /src/.build/YOUR_APP_NAME /app/YOUR_APP_NAME
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/YOUR_APP_NAME"]