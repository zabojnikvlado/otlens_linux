BINDIR := bin
SENSOR_BIN := $(BINDIR)/otlens
CENTRAL_BIN := $(BINDIR)/otlens-central

.PHONY: all build build-sensor build-central test test-race fmt vet clean

all: build

build: build-sensor build-central

build-sensor:
	mkdir -p $(BINDIR)
	go build -o $(SENSOR_BIN) ./cmd/otlens

build-central:
	mkdir -p $(BINDIR)
	go build -o $(CENTRAL_BIN) ./cmd/otlens-central

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
