# Build binary
build:
	go build -o bin/syslog-platform cmd/server/main.go
	go build -o bin/syslog-loadtest scripts/loadtest.go

# Start Docker Desktop containers
docker-up:
	docker compose up -d

# Stop Docker Desktop containers
docker-down:
	docker compose down

# Run unit tests
test:
	go test -v ./internal/...

# Run local server
run:
	go run cmd/server/main.go

# Run synthetic load test (1,000 EPS for 10s)
loadtest:
	go run scripts/loadtest.go -target 127.0.0.1:514 -eps 1000 -duration 10s
