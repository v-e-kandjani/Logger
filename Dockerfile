# Dockerfile for Syslog Platform (Go Backend + Web Dashboard)
# Since the binary is already natively built for Linux/cross-compilation or can be copied directly:
# Build locally with: CGO_ENABLED=0 GOOS=linux go build -o bin/syslog-platform-linux ./cmd/server/main.go

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

# Copy compiled Linux binary
COPY bin/syslog-platform-linux /opt/syslog-platform/bin/syslog-platform

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
