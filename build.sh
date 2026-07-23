#!/usr/bin/env bash
set -euo pipefail

mkdir -p bin

go build -o bin/otlens ./cmd/otlens
go build -o bin/otlens-central ./cmd/otlens-central

echo "Built:"
echo "  bin/otlens"
echo "  bin/otlens-central"
