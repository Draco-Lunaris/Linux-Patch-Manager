#!/usr/bin/env bash
# =============================================================================
# Linux Patch Manager — Initial Host Setup Script
# =============================================================================
# Run as root on the Ubuntu 24.04 Patch Manager host.
# This script:
#   - Creates the service user/group
#   - Creates required directories with correct permissions
#   - Installs PostgreSQL if not present
#   - Creates the database and user
#   - Copies configuration and binaries
#   - Installs systemd units
#   - Generates initial Ed25519 JWT keys
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && error "This script must be run as root."

SERVICE_USER="patch-manager"
SERVICE_GROUP="patch-manager"
CONFIG_DIR="/etc/patch-manager"
LOG_DIR="/var/log/patch-manager"
DATA_DIR="/opt/patch-manager"
FRONTEND_DIR="/usr/share/patch-manager/frontend"
BIN_DIR="/usr/local/bin"
DB_NAME="patch_manager"
DB_USER="patch_manager"
SYSTEMD_DIR="/etc/systemd/system"

info "=== Linux Patch Manager Setup ==="

# -----------------------------------------------------------------------
# 1. Create service user
# -----------------------------------------------------------------------
info "Creating service user '${SERVICE_USER}'..."
if ! id "${SERVICE_USER}" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --comment "Linux Patch Manager service account" \
        "${SERVICE_USER}"
    info "User '${SERVICE_USER}' created."
else
    warn "User '${SERVICE_USER}' already exists, skipping."
fi

# -----------------------------------------------------------------------
# 2. Create required directories
# -----------------------------------------------------------------------
info "Creating directories..."
mkdir -p \
    "${CONFIG_DIR}/ca" \
    "${CONFIG_DIR}/certs" \
    "${CONFIG_DIR}/jwt" \
    "${CONFIG_DIR}/tls" \
    "${LOG_DIR}" \
    "${DATA_DIR}" \
    "${FRONTEND_DIR}"

chown -R "${SERVICE_USER}:${SERVICE_GROUP}" \
    "${CONFIG_DIR}" \
    "${LOG_DIR}" \
    "${DATA_DIR}" \
    "${FRONTEND_DIR}"

chmod 750 "${CONFIG_DIR}/ca" "${CONFIG_DIR}/jwt"
info "Directories created."

# -----------------------------------------------------------------------
# 3. Install PostgreSQL 16 if not present
# -----------------------------------------------------------------------
if ! command -v psql &>/dev/null; then
    info "Installing PostgreSQL 16..."
    apt-get update -qq
    apt-get install -y postgresql-16
    systemctl enable --now postgresql
else
    info "PostgreSQL already installed: $(psql --version)"
fi

# -----------------------------------------------------------------------
# 4. Create database and user
# -----------------------------------------------------------------------
info "Creating database '${DB_NAME}' and user '${DB_USER}'..."
DB_PASSWORD=$(openssl rand -base64 32)

sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${DB_USER}') THEN
        CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASSWORD}';
    END IF;
END
\$\$;

SELECT 'CREATE DATABASE ${DB_NAME} OWNER ${DB_USER}'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${DB_NAME}')\\gexec
SQL

DB_URL="postgres://${DB_USER}:${DB_PASSWORD}@localhost/${DB_NAME}"
info "Database ready. Connection URL (save this!):"
echo "  ${DB_URL}"

# -----------------------------------------------------------------------
# 5. Write connection URL to config if example exists
# -----------------------------------------------------------------------
CONFIG_DEST="${CONFIG_DIR}/config.toml"
if [[ ! -f "${CONFIG_DEST}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    EXAMPLE="${SCRIPT_DIR}/../config/config.example.toml"
    if [[ -f "${EXAMPLE}" ]]; then
        cp "${EXAMPLE}" "${CONFIG_DEST}"
        sed -i "s|postgres://patch_manager:CHANGEME@localhost/patch_manager|${DB_URL}|" "${CONFIG_DEST}"
        chown "${SERVICE_USER}:${SERVICE_GROUP}" "${CONFIG_DEST}"
        chmod 640 "${CONFIG_DEST}"
        info "Config written to ${CONFIG_DEST} with database URL."
    else
        warn "config.example.toml not found; create ${CONFIG_DEST} manually."
    fi
else
    warn "${CONFIG_DEST} already exists; database URL NOT updated automatically."
    warn "Ensure the database URL is set: ${DB_URL}"
fi

# -----------------------------------------------------------------------
# 6. Generate Ed25519 JWT keys
# -----------------------------------------------------------------------
JWT_SIGNING="${CONFIG_DIR}/jwt/signing.pem"
JWT_VERIFY="${CONFIG_DIR}/jwt/verify.pem"

if [[ ! -f "${JWT_SIGNING}" ]]; then
    info "Generating Ed25519 JWT signing key..."
    openssl genpkey -algorithm ed25519 -out "${JWT_SIGNING}"
    openssl pkey -in "${JWT_SIGNING}" -pubout -out "${JWT_VERIFY}"
    chown "${SERVICE_USER}:${SERVICE_GROUP}" "${JWT_SIGNING}" "${JWT_VERIFY}"
    chmod 600 "${JWT_SIGNING}"
    chmod 644 "${JWT_VERIFY}"
    info "JWT keys generated."
else
    warn "JWT signing key already exists at ${JWT_SIGNING}, skipping."
fi

# -----------------------------------------------------------------------
# 7. Install systemd units
# -----------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for unit in patch-manager-web.service patch-manager-worker.service; do
    SRC="${SCRIPT_DIR}/../systemd/${unit}"
    if [[ -f "${SRC}" ]]; then
        cp "${SRC}" "${SYSTEMD_DIR}/${unit}"
        info "Installed systemd unit: ${unit}"
    else
        warn "Systemd unit not found: ${SRC}"
    fi
done

systemctl daemon-reload
info "systemd units installed and daemon reloaded."

# -----------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------
info "=== Setup complete ==="
info "Next steps:"
echo "  1. Build and install binaries:  cargo build --release"
echo "     cp target/release/pm-web target/release/pm-worker ${BIN_DIR}/"
echo "  2. Build and install frontend:  scripts/build-frontend.sh"
echo "  3. Review ${CONFIG_DEST}"
echo "  4. Enable services:"
echo "       systemctl enable --now patch-manager-web patch-manager-worker"
