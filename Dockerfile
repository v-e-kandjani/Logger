# Dockerfile for Valtrivo LogSeal (Go Backend + Web Dashboard)
# Multi-stage build compiles Go binary cleanly inside container without host prerequisites

# Stage 1: Compile Go binary
FROM golang:alpine AS builder

WORKDIR /app

ARG COMMIT_SHA=""
ARG VERSION=""
ARG BUILD_DATE=""

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build static Linux binaries (sanitize build args to prevent multiline shell syntax errors)
RUN COMMIT_SHA="$(printf '%s' "$COMMIT_SHA" | head -n1 | tr -d '\r\n')"; \
    VERSION="$(printf '%s' "$VERSION" | head -n1 | tr -d '\r\n')"; \
    BUILD_DATE="$(printf '%s' "$BUILD_DATE" | head -n1 | tr -d '\r\n')"; \
    if [ -n "$COMMIT_SHA" ] && [ -n "$VERSION" ] && [ -n "$BUILD_DATE" ]; then \
        CGO_ENABLED=0 GOOS=linux go build -trimpath \
        -ldflags="-s -w -X github.com/syslog-platform/logger/internal/version.CommitSHA=${COMMIT_SHA} -X github.com/syslog-platform/logger/internal/version.Version=${VERSION} -X github.com/syslog-platform/logger/internal/version.BuildDate=${BUILD_DATE}" \
        -o /app/bin/syslog-platform ./cmd/server/main.go; \
    else \
        CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /app/bin/syslog-platform ./cmd/server/main.go; \
    fi
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /app/bin/logseal-proxy ./cmd/proxy/main.go

# Stage 2: Minimal runtime image with Git and Go toolchain for dynamic web & CLI upgrades
FROM alpine:3.20

WORKDIR /opt/syslog-platform

# Install runtime utilities, OpenJDK 17 for TÜBİTAK KamuSM, and git + go toolchain for dynamic updates
RUN apk add --no-cache ca-certificates tzdata curl bash openjdk17-jre git go

# Set environment for Go compilation
ENV CGO_ENABLED=0
ENV GOPATH=/root/go

# Create production directory layout
RUN mkdir -p /opt/syslog-platform/bin \
             /opt/syslog-platform/config \
             /opt/syslog-platform/data/spool \
             /opt/syslog-platform/data/branding \
             /opt/syslog-platform/archive \
             /opt/syslog-platform/timestamp-client \
             /opt/syslog-platform/web/templates \
             /opt/syslog-platform/web/static \
             /opt/syslog-platform/scripts \
             /opt/syslog-platform/docs \
             /opt/syslog-platform/cmd \
             /opt/syslog-platform/internal \
             /opt/syslog-platform/migrations

# Copy compiled Linux binaries from builder stage
COPY --from=builder /app/bin/syslog-platform /opt/syslog-platform/bin/syslog-platform
COPY --from=builder /app/bin/logseal-proxy /opt/syslog-platform/bin/logseal-proxy

# Copy Go module descriptors and source tree to allow in-place go mod download and recompile
COPY go.mod go.sum /opt/syslog-platform/
COPY cmd/ /opt/syslog-platform/cmd/
COPY internal/ /opt/syslog-platform/internal/
COPY migrations/ /opt/syslog-platform/migrations/

# Copy scripts, web assets, and documentation
COPY scripts/ /opt/syslog-platform/scripts/
COPY docs/ /opt/syslog-platform/docs/
COPY *.md /opt/syslog-platform/
COPY web/templates/ /opt/syslog-platform/web/templates/
COPY web/static/ /opt/syslog-platform/web/static/

# Copy config
COPY config/ /opt/syslog-platform/config/

# Expose ports
EXPOSE 5514/udp 5514/tcp 6514/tcp 8080/tcp 8443/tcp

HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
  CMD curl -f http://127.0.0.1:8080/api/v1/system/health || exit 1

ENTRYPOINT ["/opt/syslog-platform/bin/syslog-platform"]
CMD ["--config", "/opt/syslog-platform/config/config.yaml"]
