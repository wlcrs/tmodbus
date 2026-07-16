#!/bin/bash
set -euo pipefail

# Skip download if the binary is already present (e.g. restored from CI cache)
if [ -f "diagslave" ]; then
    echo "diagslave binary already present, skipping download."
    exit 0
fi

# Download URL
URL="https://www.modbusdriver.com/downloads/diagslave.tgz"
TEMP_TGZ=$(mktemp)

# Clean up temporary file on exit
cleanup() {
    rm -f "$TEMP_TGZ"
}
trap cleanup EXIT

echo "Downloading diagslave..."
if command -v curl >/dev/null 2>&1; then
    curl -sSL "$URL" -o "$TEMP_TGZ"
elif command -v wget >/dev/null 2>&1; then
    wget -q "$URL" -O "$TEMP_TGZ"
else
    echo "Error: curl or wget is required to download diagslave." >&2
    exit 1
fi

echo "Extracting x86_64 binary..."
# Extract specifically the x86_64-linux-gnu version and output directly
tar -O -xf "$TEMP_TGZ" diagslave/x86_64-linux-gnu/diagslave > diagslave
chmod +x diagslave

echo "Diagslave binary successfully set up."
