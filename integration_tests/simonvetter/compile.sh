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

# Skip build if binaries are already present (e.g. restored from CI cache)
if ! $FORCE && [ -f "client" ] && [ -f "server" ]; then
    echo "simonvetter binaries already present, skipping build."
    exit 0
fi

docker run --rm -v "$(pwd)":/work  -w /work golang:1.22 go build -o client client.go
docker run --rm -v "$(pwd)":/work  -w /work golang:1.22 go build -o server server.go
