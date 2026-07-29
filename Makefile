# OTLens build targets. Sensor and Central use separate runtime config files.

BINDIR := bin
SENSOR_BIN := $(BINDIR)/otlens
CENTRAL_BIN := $(BINDIR)/otlens-central

.PHONY: all build build-sensor build-central build-linux-sensor build-windows-central build-windows build-linux test test-race fmt fmt-check vet frontend-check pdf-smoke verify clean

all: build

build: build-sensor build-central

build-sensor:
	mkdir -p $(BINDIR)
	go build -buildvcs=false -o $(SENSOR_BIN) ./cmd/otlens

build-central:
	mkdir -p $(BINDIR)
	go build -buildvcs=false -o $(CENTRAL_BIN) ./cmd/otlens-central

# Production deployment targets:
# Linux sensor: packet capture + local SQLite detection.
build-linux-sensor:
	mkdir -p $(BINDIR)
	GOOS=linux GOARCH=amd64 go build -buildvcs=false -o $(BINDIR)/otlens-linux-amd64 ./cmd/otlens

# Windows central: management API + PostgreSQL client + correlation/management services.
build-windows-central:
	mkdir -p $(BINDIR)
	GOOS=windows GOARCH=amd64 go build -buildvcs=false -o $(BINDIR)/otlens-central-windows-amd64.exe ./cmd/otlens-central

build-windows: build-windows-central

build-linux: build-linux-sensor

test:
	go test -buildvcs=false ./...

test-race:
	go test -buildvcs=false -race ./...

fmt:
	gofmt -w $$(find . -type f -name '*.go' -not -path './vendor/*')

fmt-check:
	@test -z "$$(gofmt -l $$(find . -type f -name '*.go' -not -path './vendor/*'))" || (echo "Go files require gofmt"; gofmt -l $$(find . -type f -name '*.go' -not -path './vendor/*'); exit 1)

frontend-check:
	node --check web/central/app.js

pdf-smoke:
	go test -buildvcs=false ./internal/central -run 'Test.*PDF'

verify: fmt-check frontend-check vet test build

vet:
	go vet ./...

clean:
	rm -rf $(BINDIR)
