#!/usr/bin/env bash
set -euo pipefail

mkdir -p bin

go build -buildvcs=false -o bin/otlens ./cmd/otlens
go build -buildvcs=false -o bin/otlens-central ./cmd/otlens-central

echo "Built:"
echo "  bin/otlens"
echo "  bin/otlens-central"
