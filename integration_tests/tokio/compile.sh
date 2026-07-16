#!/bin/bash
set -euo pipefail

FORCE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--force)
      FORCE=true
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

# Skip build if binaries are already present (e.g. restored from CI cache) and no force flag
if ! $FORCE && [ -f "target/release/tokio-server" ] && [ -f "target/release/tokio-client" ]; then
    echo "tokio binaries already present, skipping build."
    exit 0
fi

docker run --rm -v "$(pwd):/work" -w /work rust:1-trixie cargo build --release
