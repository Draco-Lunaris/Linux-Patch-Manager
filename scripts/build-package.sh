#!/usr/bin/env bash
# =============================================================================
# Linux Patch Manager — Build .deb Package for Ubuntu 24.04
# =============================================================================
# Produces: linux-patch-manager_1.0.0-1_amd64.deb
# Prerequisites:
#   - Rust toolchain (cargo, rustc >= 1.75)
#   - Node.js >= 18 + npm
#   - dpkg-deb
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="1.1.18"
RELEASE="1"
PKG_NAME="linux-patch-manager"
DEB_NAME="${PKG_NAME}_${VERSION}-${RELEASE}_amd64.deb"
BUILD_DIR="${PROJECT_ROOT}/package-build"

info "=== Linux Patch Manager — Package Build ==="
info "Version: ${VERSION}-${RELEASE}"
info "Target:  Ubuntu 24.04 (noble) amd64"
echo

# ---------------------------------------------------------------------------
# 1. Build Rust binaries (release mode)
# ---------------------------------------------------------------------------
info "Step 1/5: Building Rust binaries (release mode)..."
cd "${PROJECT_ROOT}"
cargo build --release 2>&1 | tail -5

# Verify binaries exist
for bin in pm-web pm-worker; do
    [[ -f "${PROJECT_ROOT}/target/release/${bin}" ]] || error "${bin} not found in target/release/"
done
info "Rust binaries built successfully."

# Strip debug symbols for smaller package
for bin in pm-web pm-worker; do
    strip "${PROJECT_ROOT}/target/release/${bin}" 2>/dev/null || warn "strip failed for ${bin} (may already be stripped)"
done
info "Binaries stripped."

# ---------------------------------------------------------------------------
# 2. Build frontend
# ---------------------------------------------------------------------------
info "Step 2/5: Building frontend..."
cd "${PROJECT_ROOT}/frontend"

if [[ ! -d "node_modules" ]]; then
    info "Installing frontend dependencies..."
    npm ci --production 2>&1 | tail -3
fi

npm run build 2>&1 | tail -5
[[ -d "${PROJECT_ROOT}/frontend/dist" ]] || error "Frontend build failed: dist/ not found"
info "Frontend built successfully."

# ---------------------------------------------------------------------------
# 3. Assemble package directory structure
# ---------------------------------------------------------------------------
info "Step 3/5: Assembling package structure..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/DEBIAN"
mkdir -p "${BUILD_DIR}/usr/local/bin"
mkdir -p "${BUILD_DIR}/usr/share/patch-manager/frontend"
mkdir -p "${BUILD_DIR}/usr/share/patch-manager/migrations"
mkdir -p "${BUILD_DIR}/lib/systemd/system"

# Binaries
cp "${PROJECT_ROOT}/target/release/pm-web" "${BUILD_DIR}/usr/local/bin/pm-web"
cp "${PROJECT_ROOT}/target/release/pm-worker" "${BUILD_DIR}/usr/local/bin/pm-worker"
cp "${PROJECT_ROOT}/scripts/backup.sh" "${BUILD_DIR}/usr/local/bin/backup.sh"
cp "${PROJECT_ROOT}/scripts/setup.sh" "${BUILD_DIR}/usr/local/bin/setup.sh"
chmod 755 "${BUILD_DIR}/usr/local/bin/pm-web"
chmod 755 "${BUILD_DIR}/usr/local/bin/pm-worker"
chmod 700 "${BUILD_DIR}/usr/local/bin/backup.sh"
chmod 755 "${BUILD_DIR}/usr/local/bin/setup.sh"

# Frontend
cp -r "${PROJECT_ROOT}/frontend/dist/"* "${BUILD_DIR}/usr/share/patch-manager/frontend/"

# Config example
cp "${PROJECT_ROOT}/config/config.example.toml" "${BUILD_DIR}/usr/share/patch-manager/config.example.toml"

# Migrations
cp "${PROJECT_ROOT}/migrations/"*.sql "${BUILD_DIR}/usr/share/patch-manager/migrations/"

# Systemd units
cp "${PROJECT_ROOT}/systemd/patch-manager-web.service" "${BUILD_DIR}/lib/systemd/system/"
cp "${PROJECT_ROOT}/systemd/patch-manager-worker.service" "${BUILD_DIR}/lib/systemd/system/"
cp "${PROJECT_ROOT}/systemd/patch-manager.target" "${BUILD_DIR}/lib/systemd/system/"

# DEBIAN control files
cp "${PROJECT_ROOT}/debian/control" "${BUILD_DIR}/DEBIAN/control"
cp "${PROJECT_ROOT}/debian/postinst" "${BUILD_DIR}/DEBIAN/postinst"
cp "${PROJECT_ROOT}/debian/prerm" "${BUILD_DIR}/DEBIAN/prerm"
cp "${PROJECT_ROOT}/debian/postrm" "${BUILD_DIR}/DEBIAN/postrm"
chmod 755 "${BUILD_DIR}/DEBIAN/postinst" "${BUILD_DIR}/DEBIAN/prerm" "${BUILD_DIR}/DEBIAN/postrm"

 # Update Version in control file to match Cargo.toml version
 sed -i "s/^Version: .*/Version: ${VERSION}-${RELEASE}/" "${BUILD_DIR}/DEBIAN/control"

# Calculate installed size (in KB)
INSTALLED_SIZE=$(du -sk "${BUILD_DIR}" | cut -f1)
sed -i "s/^Installed-Size: .*/Installed-Size: ${INSTALLED_SIZE}/" "${BUILD_DIR}/DEBIAN/control"

info "Package structure assembled (${INSTALLED_SIZE} KB)."

# ---------------------------------------------------------------------------
# 4. Build .deb package
# ---------------------------------------------------------------------------
info "Step 4/5: Building .deb package..."
dpkg-deb --build "${BUILD_DIR}" "${PROJECT_ROOT}/${DEB_NAME}"
info ".deb package created: ${DEB_NAME}"

# ---------------------------------------------------------------------------
# 5. Verify and summarize
# ---------------------------------------------------------------------------
info "Step 5/5: Verifying package..."
dpkg-deb --info "${PROJECT_ROOT}/${DEB_NAME}"
echo
dpkg-deb --contents "${PROJECT_ROOT}/${DEB_NAME}" | head -20 || true
echo

PKG_SIZE=$(du -h "${PROJECT_ROOT}/${DEB_NAME}" | cut -f1)

info "=== Package Build Complete ==="
info "Package: ${DEB_NAME}"
info "Size:   ${PKG_SIZE}"
echo
echo -e "${CYAN}Installation instructions:${NC}"
echo "  1. Copy ${DEB_NAME} to the target Ubuntu 24.04 host"
echo "  2. Install:  sudo dpkg -i ${DEB_NAME}"
echo "  3. Or with auto-deps:  sudo apt install ./${DEB_NAME}"
echo "  4. Configure database URL in /etc/patch-manager/config.toml"
echo "  5. Start:  systemctl enable --now patch-manager.target"
echo

# Cleanup build directory
rm -rf "${BUILD_DIR}"
info "Build directory cleaned up."
