# ──────────────────────────────────────────────────────────────────────
# Stage 1 — build
# ──────────────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Cache deps first
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -extldflags=-static" \
    -trimpath \
    -o fileserv .

# ──────────────────────────────────────────────────────────────────────
# Stage 2 — runtime (scratch + CA certs for remote fetch)
# ──────────────────────────────────────────────────────────────────────
FROM alpine:3.20 AS runtime

# ca-certificates needed for HTTPS fetch; tzdata for correct timestamps
RUN apk add --no-cache ca-certificates tzdata && \
    update-ca-certificates

# Non-root user
RUN addgroup -S fileserv && adduser -S -G fileserv fileserv

WORKDIR /app
COPY --from=builder /src/fileserv /app/fileserv

# Data volumes
RUN mkdir -p /app/data/files && chown -R fileserv:fileserv /app/data

USER fileserv

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/api/health || exit 1

ENTRYPOINT ["/app/fileserv"]
