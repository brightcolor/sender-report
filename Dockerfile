# syntax=docker/dockerfile:1.7

# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS builder
WORKDIR /src

# build-base provides GCC for cgo (go-sqlite3).
# Cache the apk layer so it is only re-downloaded when the alpine index changes.
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache build-base

# Copy dependency manifests first — rebuilt only when go.mod or go.sum change
COPY go.mod go.sum ./

# Download modules with a persistent cache mount
RUN --mount=type=cache,target=/root/go/pkg/mod \
    go mod download

# Copy source and build.
# Both cache mounts stay warm across builds — only changed packages recompile.
COPY . .
RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/mailprobe ./cmd/mailprobe

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata sqlite-libs su-exec
WORKDIR /app
COPY --from=builder /out/mailprobe        /app/mailprobe
COPY internal/web/templates               /app/internal/web/templates
COPY internal/web/static                  /app/internal/web/static
COPY entrypoint.sh                        /app/entrypoint.sh
RUN addgroup -S app && adduser -S -G app app \
    && mkdir -p /data && chown -R app:app /data /app \
    && chmod +x /app/entrypoint.sh
EXPOSE 8080 2525
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/app/entrypoint.sh"]
