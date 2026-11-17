#!/usr/bin/env bash
# Build the developer-side signer; no key generation or runtime service change.
set -euo pipefail
XEAS_RELEASE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$XEAS_RELEASE_ROOT"
mkdir -p build
GOWORK=off CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags='-s -w' -o build/xeas-release ./cmd/xeas-release
printf '%s\n' 'Release tool: build/xeas-release'
