#!/usr/bin/env bash
# Sign reviewed RPMs locally. The private key never enters a release directory.
set -euo pipefail
XEAS_RELEASE_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
XEAS_RELEASE_KEY=${XEAS_RELEASE_KEY:-/root/.local/share/xe-antishell-release/publisher-key.pem}
XEAS_RELEASE_OUT=${XEAS_RELEASE_OUT:-"$XEAS_RELEASE_ROOT/dist/release"}
if (( $# == 0 )); then
  printf '%s\n' 'Usage: scripts/sign-release.sh AGENT.rpm [AGENT.rpm ...]' >&2
  exit 2
fi
"$XEAS_RELEASE_ROOT/scripts/build-release-tool.sh"
mkdir -p -- "$XEAS_RELEASE_OUT"
for XEAS_RELEASE_RPM in "$@"; do
  XEAS_RELEASE_RPM=$(realpath -- "$XEAS_RELEASE_RPM")
  XEAS_RELEASE_NAME=${XEAS_RELEASE_RPM##*/}
  [[ "$XEAS_RELEASE_NAME" == xe-antishell-*.rpm ]] || { printf '%s\n' 'Only agent RPMs are accepted.' >&2; exit 1; }
  if [[ -e "$XEAS_RELEASE_OUT/$XEAS_RELEASE_NAME.manifest.json" ]]; then
    "$XEAS_RELEASE_ROOT/build/xeas-release" verify --manifest "$XEAS_RELEASE_OUT/$XEAS_RELEASE_NAME.manifest.json" --rpm "$XEAS_RELEASE_RPM"
    continue
  fi
  "$XEAS_RELEASE_ROOT/build/xeas-release" prepare --rpm "$XEAS_RELEASE_RPM" --out "$XEAS_RELEASE_OUT/$XEAS_RELEASE_NAME.unsigned.json"
  "$XEAS_RELEASE_ROOT/build/xeas-release" sign --rpm "$XEAS_RELEASE_RPM" --manifest "$XEAS_RELEASE_OUT/$XEAS_RELEASE_NAME.unsigned.json" --key "$XEAS_RELEASE_KEY" --out "$XEAS_RELEASE_OUT/$XEAS_RELEASE_NAME.manifest.json"
  "$XEAS_RELEASE_ROOT/build/xeas-release" verify --manifest "$XEAS_RELEASE_OUT/$XEAS_RELEASE_NAME.manifest.json" --rpm "$XEAS_RELEASE_RPM"
done
