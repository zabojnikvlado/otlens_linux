BINDIR := bin
SENSOR_BIN := $(BINDIR)/otlens
CENTRAL_BIN := $(BINDIR)/otlens-central

.PHONY: all build build-sensor build-central build-linux-sensor build-windows-central build-windows build-linux test test-race fmt vet clean

all: build

build: build-sensor build-central

build-sensor:
	mkdir -p $(BINDIR)
	go build -o $(SENSOR_BIN) ./cmd/otlens

build-central:
	mkdir -p $(BINDIR)
	go build -o $(CENTRAL_BIN) ./cmd/otlens-central

# Production deployment targets:
# Linux sensor: packet capture + local SQLite detection.
build-linux-sensor:
	mkdir -p $(BINDIR)
	GOOS=linux GOARCH=amd64 go build -o $(BINDIR)/otlens-linux-amd64 ./cmd/otlens

# Windows central: management API + PostgreSQL client + correlation/management services.
build-windows-central:
	mkdir -p $(BINDIR)
	GOOS=windows GOARCH=amd64 go build -o $(BINDIR)/otlens-central-windows-amd64.exe ./cmd/otlens-central

build-windows: build-windows-central

build-linux: build-linux-sensor

test:
	go test ./...

test-race:
	go test -race ./...

fmt:
	gofmt -w $$(find . -type f -name '*.go' -not -path './vendor/*')

vet:
	go vet ./...

clean:
	rm -rf $(BINDIR)
