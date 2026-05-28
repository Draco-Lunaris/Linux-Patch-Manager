#!/usr/bin/env bash
# =============================================================================
# Linux Patch Manager — Frontend Build Script
# =============================================================================
# Builds the React + TypeScript SPA and copies output to the system frontend dir.
# Run from the repository root.
# =============================================================================

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FRONTEND_DIR="${REPO_ROOT}/frontend"
DEST_DIR="${1:-/usr/share/patch-manager/frontend}"

info "Building React SPA..."
cd "${FRONTEND_DIR}"

# Install dependencies if node_modules not present
if [[ ! -d node_modules ]]; then
    info "Installing npm dependencies..."
    npm ci
fi

# Build
info "Running vite build..."
npm run build

# Deploy to destination
info "Copying build output to ${DEST_DIR}..."
mkdir -p "${DEST_DIR}"
rm -rf "${DEST_DIR:?}/"
cp -r dist/* "${DEST_DIR}/"

info "Frontend build complete → ${DEST_DIR}"
