#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-1.2.0}"
DIST_DIR="./dist"
mkdir -p "${DIST_DIR}"

echo "Compiling parsvpn static binaries (version ${VERSION})..."

LDFLAGS="-s -w -X 'main.Version=${VERSION}' -X 'main.BuildTime=$(date -u +'%Y-%m-%dT%H:%M:%SZ')'"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="${LDFLAGS}" \
  -o "${DIST_DIR}/parsvpn-linux-amd64" ./cmd/parsvpn

CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="${LDFLAGS}" \
  -o "${DIST_DIR}/parsvpn-linux-arm64" ./cmd/parsvpn

echo "Build complete:"
ls -la "${DIST_DIR}"
