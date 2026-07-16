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
if ! $FORCE && [ -f "target/release/server" ] && [ -f "target/release/client" ] && [ -f "target/release/ascii-server" ]; then
    echo "rmodbus binaries already present, skipping build."
    exit 0
fi

docker run --rm -v "$(pwd):/work" -w /work rust:1-trixie cargo build --release
