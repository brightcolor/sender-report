# syntax=docker/dockerfile:1.7

# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder
WORKDIR /src

# No build-base/GCC needed: modernc.org/sqlite is pure Go (CGO_ENABLED=0).
# Only cache the apk layer for any future tool additions.
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache

# Copy dependency manifests first — rebuilt only when go.mod or go.sum change.
COPY go.mod go.sum ./

# Download modules with a persistent cache mount.
RUN --mount=type=cache,target=/root/go/pkg/mod \
    go mod download

# Copy source and build. Cache mounts stay warm across builds.
COPY . .
RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sender-report ./cmd/sender-report

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.21
# ca-certificates: HTTPS outbound (DNSBL, SpamAssassin, Rspamd).
# tzdata: correct timezone handling.
# su-exec: privilege drop in entrypoint.
# No sqlite-libs needed: SQLite is embedded in the binary.
RUN apk add --no-cache ca-certificates tzdata su-exec
WORKDIR /app
COPY --from=builder /out/sender-report        /app/sender-report
COPY internal/web/templates                   /app/internal/web/templates
COPY internal/web/static                      /app/internal/web/static
COPY entrypoint.sh                            /app/entrypoint.sh
RUN addgroup -S app && adduser -S -G app app \
    && mkdir -p /data && chown -R app:app /data /app \
    && chmod +x /app/entrypoint.sh
EXPOSE 8080 2525
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/app/entrypoint.sh"]
