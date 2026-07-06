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
#   - Generates internal CA and CA-signed web server certificate
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
BACKUP_DIR="/var/backups/patch-manager"
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
    "${CONFIG_DIR}/keys" \
    "${CONFIG_DIR}/tls" \
    "${LOG_DIR}" \
    "${DATA_DIR}" \
    "${FRONTEND_DIR}" \
    "${BACKUP_DIR}"

chown -R "${SERVICE_USER}:${SERVICE_GROUP}" \
    "${CONFIG_DIR}" \
    "${LOG_DIR}" \
    "${DATA_DIR}" \
    "${FRONTEND_DIR}"

chmod 750 "${CONFIG_DIR}/ca" "${CONFIG_DIR}/jwt" "${CONFIG_DIR}/keys"
chmod 700 "${BACKUP_DIR}"

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

# Grant schema permissions (PostgreSQL 15+ requires explicit grants)
sudo -u postgres psql -v ON_ERROR_STOP=1 -d ${DB_NAME} <<SQL
GRANT USAGE ON SCHEMA public TO ${DB_USER};
GRANT CREATE ON SCHEMA public TO ${DB_USER};
GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};
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
# 6b. Generate CA and CA-signed TLS certificate for HTTPS
# -----------------------------------------------------------------------
CA_KEY="${CONFIG_DIR}/ca/ca.key"
CA_CERT="${CONFIG_DIR}/ca/ca.crt"
TLS_CERT="${CONFIG_DIR}/tls/web.crt"
TLS_KEY="${CONFIG_DIR}/tls/web.key"
TLS_CSR="${CONFIG_DIR}/tls/web.csr"

# Generate CA if not present (pm-ca will load this on startup)
if [[ ! -f "${CA_CERT}" ]]; then
    info "Generating internal Certificate Authority (ECDSA P-256, 10-year validity)..."
    openssl ecparam -genkey -name prime256v1 -noout -out "${CA_KEY}"
    openssl req -new -x509 -key "${CA_KEY}" -out "${CA_CERT}" \
        -days 3650 \
        -subj "/CN=Patch Manager Root CA/O=Patch Manager" \
        -addext "basicConstraints=critical,CA:true" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
    chown "${SERVICE_USER}:${SERVICE_GROUP}" "${CA_KEY}" "${CA_CERT}"
    chmod 600 "${CA_KEY}" "${CA_CERT}"
    info "Internal CA generated."
else
    info "Internal CA already exists at ${CA_CERT}, skipping."
fi

# Generate web server certificate signed by the internal CA
if [[ ! -f "${TLS_CERT}" ]]; then
    info "Generating CA-signed web server certificate (valid 365 days)..."
    HOSTNAME_FQDN=$(hostname -f 2>/dev/null || echo "localhost")
    HOSTNAME_SHORT=$(hostname -s 2>/dev/null || echo "localhost")

    # Warn if hostname -f does not return a proper FQDN (no domain part).
    # This causes the TLS cert CN to be a short hostname, which breaks
    # agent CRL fetches that verify the server cert hostname against the
    # manager_url. See issue: agents report "CRL expired" because reqwest
    # rejects the TLS connection on hostname mismatch.
    if [[ "${HOSTNAME_FQDN}" == "${HOSTNAME_SHORT}" || "${HOSTNAME_FQDN}" != *.* ]]; then
        warn "hostname -f returned '${HOSTNAME_FQDN}' which does not appear to be a fully-qualified domain name (FQDN)."
        warn "The TLS certificate will be issued with CN=${HOSTNAME_FQDN}. If agents connect via a different hostname (e.g. manager.example.com),"
        warn "CRL fetches will fail with a TLS hostname mismatch error. To fix:"
        warn "  1. Set the system FQDN: hostnamectl set-hostname $(hostname -s).your-domain.com"
        warn "  2. Add an entry to /etc/hosts: <IP> <short>.your-domain.com <short>"
        warn "  3. Re-run this setup script to regenerate the certificate."
        warn "Continuing with CN=${HOSTNAME_FQDN}..."
    fi

    # Get the host's primary IP address for SAN
    HOST_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || echo "127.0.0.1")

    # Generate ECDSA P-256 private key for web server
    openssl ecparam -genkey -name prime256v1 -noout -out "${TLS_KEY}"

    # Generate CSR with SANs
    openssl req -new -key "${TLS_KEY}" -out "${TLS_CSR}" \
        -subj "/CN=${HOSTNAME_FQDN}/O=Patch Manager" \
        -addext "subjectAltName=DNS:${HOSTNAME_FQDN},DNS:${HOSTNAME_SHORT},DNS:localhost,IP:${HOST_IP},IP:127.0.0.1,IP:::1"

    # Sign with the internal CA
    openssl x509 -req -in "${TLS_CSR}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" \
        -CAcreateserial -days 365 -out "${TLS_CERT}" \
        -extfile <(printf "subjectAltName=DNS:${HOSTNAME_FQDN},DNS:${HOSTNAME_SHORT},DNS:localhost,IP:${HOST_IP},IP:127.0.0.1,IP:::1\nextendedKeyUsage=serverAuth")

    # Clean up CSR
    rm -f "${TLS_CSR}"

    chown "${SERVICE_USER}:${SERVICE_GROUP}" "${TLS_CERT}" "${TLS_KEY}"
    chmod 644 "${TLS_CERT}"
    chmod 600 "${TLS_KEY}"
    info "CA-signed web server certificate generated for ${HOSTNAME_FQDN}."
else
    warn "TLS certificate already exists at ${TLS_CERT}, skipping."
fi

# -----------------------------------------------------------------------
# 6c. Generate manager's own mTLS client certificate (signed by CA)
# -----------------------------------------------------------------------
CLIENT_CERT="${CONFIG_DIR}/certs/client.crt"
CLIENT_KEY="${CONFIG_DIR}/certs/client.key"

if [[ ! -f "${CLIENT_CERT}" ]]; then
    info "Generating CA-signed manager client certificate (valid 365 days)..."
    # Ensure certs directory exists
    mkdir -p "${CONFIG_DIR}/certs"

    # Generate ECDSA P-256 private key for manager client cert
    openssl ecparam -genkey -name prime256v1 -noout -out "${CLIENT_KEY}"

    # Generate CSR
    CLIENT_CSR="${CONFIG_DIR}/certs/client.csr"
    openssl req -new -key "${CLIENT_KEY}" -out "${CLIENT_CSR}" \
        -subj "/CN=patch-manager-client/O=Patch Manager"

    # Sign with the internal CA, with extendedKeyUsage=clientAuth
    openssl x509 -req -in "${CLIENT_CSR}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" \
        -CAcreateserial -days 365 -out "${CLIENT_CERT}" \
        -extfile <(printf "extendedKeyUsage=clientAuth")

    # Clean up CSR
    rm -f "${CLIENT_CSR}"

    chown "${SERVICE_USER}:${SERVICE_GROUP}" "${CLIENT_CERT}" "${CLIENT_KEY}"
    chmod 644 "${CLIENT_CERT}"
    chmod 600 "${CLIENT_KEY}"
    info "CA-signed manager client certificate generated."
else
    warn "Manager client certificate already exists at ${CLIENT_CERT}, skipping."
fi

# -----------------------------------------------------------------------
# 7. Install systemd units
# -----------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Install systemd target
TARGET_SRC="${SCRIPT_DIR}/../systemd/patch-manager.target"
if [[ -f "${TARGET_SRC}" ]]; then
    cp "${TARGET_SRC}" "${SYSTEMD_DIR}/patch-manager.target"
    info "Installed systemd target: patch-manager.target"
fi

# Install service units
for unit in patch-manager-web.service patch-manager-worker.service; do
    SRC="${SCRIPT_DIR}/../systemd/${unit}"
    if [[ -f "${SRC}" ]]; then
        cp "${SRC}" "${SYSTEMD_DIR}/${unit}"
        info "Installed systemd unit: ${unit}"
    else
        warn "Systemd unit not found: ${SRC}"
    fi
done

# Install backup script
BACKUP_SRC="${SCRIPT_DIR}/backup.sh"
if [[ -f "${BACKUP_SRC}" ]]; then
    cp "${BACKUP_SRC}" "${BIN_DIR}/backup.sh"
    chmod 700 "${BIN_DIR}/backup.sh"
    info "Installed backup script to ${BIN_DIR}/backup.sh"
fi

systemctl daemon-reload
info "systemd units installed and daemon reloaded."

# -----------------------------------------------------------------------
# 8. Run seed migration (default admin account)
# -----------------------------------------------------------------------
SEED_MIGRATION="${SCRIPT_DIR}/../migrations/002_seed_admin.sql"
if [[ -f "${SEED_MIGRATION}" ]]; then
    info "Running seed migration for default admin account..."
    sudo -u postgres psql -d "${DB_NAME}" -f "${SEED_MIGRATION}" 2>/dev/null || \
        warn "Seed migration already applied or failed (may be idempotent)."
else
    warn "Seed migration not found: ${SEED_MIGRATION}"
fi

# -----------------------------------------------------------------------
# 9. Install backup cron job
# -----------------------------------------------------------------------
CRON_LINE="0 2 * * * /usr/local/bin/backup.sh >> /var/log/patch-manager/backup.log 2>&1"
if crontab -l 2>/dev/null | grep -qF "backup.sh"; then
    warn "Backup cron job already installed, skipping."
else
    (crontab -l 2>/dev/null; echo "${CRON_LINE}") | crontab -
    info "Nightly backup cron installed (02:00 daily)."
fi

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
echo "  5. (Optional) Set GPG_RECIPIENT in backup.sh for encrypted backups"
