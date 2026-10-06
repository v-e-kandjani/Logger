# Dockerfile for Valtrivo LogSeal (Go Backend + Web Dashboard)
# Multi-stage build compiles Go binary cleanly inside container without host prerequisites

# Stage 1: Compile Go binary
FROM golang:alpine AS builder

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build static Linux binary
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /app/bin/syslog-platform ./cmd/server/main.go

# Stage 2: Minimal runtime image
FROM alpine:3.20

WORKDIR /opt/syslog-platform

# Install runtime utilities & OpenJDK 17 for TÜBİTAK KamuSM Zaman Damgası
RUN apk add --no-cache ca-certificates tzdata curl bash openjdk17-jre

# Create production directory layout
RUN mkdir -p /opt/syslog-platform/bin \
             /opt/syslog-platform/config \
             /opt/syslog-platform/data/spool \
             /opt/syslog-platform/archive \
             /opt/syslog-platform/timestamp-client \
             /opt/syslog-platform/web/templates \
             /opt/syslog-platform/web/static

# Copy compiled Linux binary from builder stage
COPY --from=builder /app/bin/syslog-platform /opt/syslog-platform/bin/syslog-platform

# Copy web assets
COPY web/templates/ /opt/syslog-platform/web/templates/
COPY web/static/ /opt/syslog-platform/web/static/

# Copy config
COPY config/config.yaml /opt/syslog-platform/config/config.yaml

# Expose ports
EXPOSE 5514/udp 5514/tcp 6514/tcp 8080/tcp

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
  CMD curl -f http://127.0.0.1:8080/api/v1/system/health || exit 1

ENTRYPOINT ["/opt/syslog-platform/bin/syslog-platform"]
CMD ["--config", "/opt/syslog-platform/config/config.yaml"]
