#!/bin/bash
# Download latest python-build-standalone
#
# Package selection:
#   - Version: first argument or PYTHON_VERSION env var, default 3.12
#   - Architecture: second argument or auto-detected via uname -m (x86_64, aarch64)
#   - Variant: install_only_stripped — minimal runtime without debug symbols,
#     pre-installed layout (bin/ lib/ include/), ready to use directly
#   - Stability: alpha/beta/rc versions are filtered out, highest patch version selected
#
# Source: https://github.com/astral-sh/python-build-standalone
# Asset naming: cpython-{ver}+{tag}-{arch}-unknown-linux-gnu-install_only_stripped.tar.gz
#
# Usage:
#   ./download-python-standalone.sh [PYTHON_VERSION] [ARCH]
#
# Examples:
#   ./download-python-standalone.sh          # download latest stable (3.12.x) for current arch
#   ./download-python-standalone.sh 3.13     # download latest 3.13.x for current arch
#   ./download-python-standalone.sh 3.12 aarch64  # download 3.12.x for aarch64

set -euo pipefail

PYTHON_VERSION="${1:-${PYTHON_VERSION:-3.12}}"
ARCH="${2:-$(uname -m)}"
VARIANT="${ARCH}-unknown-linux-gnu-install_only_stripped"

echo "Fetching latest release info..."
RELEASE_JSON=$(curl -sfL https://raw.githubusercontent.com/astral-sh/python-build-standalone/latest-release/latest-release.json)
TAG=$(echo "$RELEASE_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['tag'])")
PREFIX=$(echo "$RELEASE_JSON" | python3 -c "import json,sys; print(json.load(sys.stdin)['asset_url_prefix'])")

echo "Latest release tag: $TAG"

echo "Finding cpython-${PYTHON_VERSION}.x asset..."
if command -v gh &>/dev/null && gh auth status &>/dev/null; then
    ASSET_NAME=$(gh release view "$TAG" --repo astral-sh/python-build-standalone \
        --json assets --jq '.assets[].name' \
      | grep -E "^cpython-${PYTHON_VERSION}\.[0-9]+" \
      | grep "${VARIANT}\.tar\.gz$" \
      | grep -v -E '(a|b|rc)[0-9]+' \
      | sort -t. -k3 -n -r | head -1)
else
    API_HEADERS=$(mktemp)
    ASSET_NAME=$(curl -sS -D "$API_HEADERS" "https://api.github.com/repos/astral-sh/python-build-standalone/releases/tags/${TAG}" \
      | python3 -c "
import json, sys, re
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(1)
pattern = re.compile(r'^cpython-${PYTHON_VERSION}\.\d+(\+|\-).*${VARIANT}\.tar\.gz\$')
matches = [a['name'] for a in data.get('assets', []) if pattern.match(a['name'])]
stable = [m for m in matches if not re.search(r'(a|b|rc)\d+', m)]
if stable:
    matches = stable
if matches:
    matches.sort(key=lambda x: [int(n) for n in re.search(r'cpython-(\d+)\.(\d+)\.(\d+)', x).groups()], reverse=True)
    print(matches[0])
else:
    sys.exit(1)
" 2>/dev/null || true)

    if [ -z "$ASSET_NAME" ]; then
        # Check if rate limited
        RESET_TS=$(grep -i "^x-ratelimit-reset:" "$API_HEADERS" 2>/dev/null | tr -d '\r' | awk '{print $2}')
        if [ -n "$RESET_TS" ]; then
            RESET_TIME=$(date -d "@$RESET_TS" 2>/dev/null || date -r "$RESET_TS" 2>/dev/null || echo "$RESET_TS")
            echo "  Hint: GitHub API rate limit may have been exceeded, resets at: $RESET_TIME" 1>&2
            echo "  Hint: Install 'gh' CLI and run 'gh auth login' to avoid rate limits." 1>&2
        fi
    fi
    rm -f "$API_HEADERS"
fi

if [ -z "$ASSET_NAME" ]; then
    echo "ERROR: No matching asset found for cpython-${PYTHON_VERSION}.x ${VARIANT}" 1>&2
    exit 1
fi

if [ -f "$ASSET_NAME" ]; then
    echo "Already exists: $ASSET_NAME"
else
    echo "Downloading: $ASSET_NAME"
    curl -fL --progress-bar -O "${PREFIX}/${ASSET_NAME}"
fi

echo ""
echo "Downloaded: $ASSET_NAME"
echo "Extract with: tar xzf $ASSET_NAME"
