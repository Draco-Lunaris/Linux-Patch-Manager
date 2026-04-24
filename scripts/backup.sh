#!/usr/bin/env bash
# =============================================================================
# Linux Patch Manager — Nightly Backup Script
# =============================================================================
# Run via cron or systemd timer.
# Performs:
#   1. pg_dump of the patch_manager database
#   2. CA material backup (/etc/patch-manager/ca/)
#   3. Config backup (/etc/patch-manager/config.toml, jwt keys, tls certs)
#     - Secrets are excluded unless GPG_RECIPIENT is set for encryption
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $(date +%Y-%m-%dT%H:%M:%S) $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $(date +%Y-%m-%dT%H:%M:%S) $*"; }
error() { echo -e "${RED}[ERROR]${NC} $(date +%Y-%m-%dT%H:%M:%S) $*" >&2; }

# ---------------------------------------------------------------------------
# Configuration (override via environment or config file)
# ---------------------------------------------------------------------------
BACKUP_DIR="${BACKUP_DIR:-/var/backups/patch-manager}"
DB_NAME="${DB_NAME:-patch_manager}"
DB_USER="${DB_USER:-patch_manager}"
CONFIG_DIR="/etc/patch-manager"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
GPG_RECIPIENT="${GPG_RECIPIENT:-}"  # Set to GPG key ID to encrypt secret backups
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
[[ $EUID -ne 0 ]] && error "This script must be run as root."
command -v pg_dump >/dev/null 2>&1 || error "pg_dump not found. Install postgresql-client."
command -v gpg >/dev/null 2>&1 || { [[ -n "${GPG_RECIPIENT}" ]] && error "GPG_RECIPIENT set but gpg not found." || true; }

mkdir -p "${BACKUP_DIR}"
chmod 700 "${BACKUP_DIR}"

BACKUP_SUCCESS=true

# ---------------------------------------------------------------------------
# 1. Database backup (pg_dump, custom format for parallel restore)
# ---------------------------------------------------------------------------
info "Starting database backup..."
DB_FILE="${BACKUP_DIR}/patch_manager_db_${TIMESTAMP}.dump"

if sudo -u postgres pg_dump -Fc -f "${DB_FILE}" "${DB_NAME}" 2>/dev/null; then
    chmod 600 "${DB_FILE}"
    chown root:root "${DB_FILE}"
    SIZE=$(du -h "${DB_FILE}" | cut -f1)
    info "Database backup complete: ${DB_FILE} (${SIZE})"
else
    error "Database backup FAILED."
    BACKUP_SUCCESS=false
fi

# ---------------------------------------------------------------------------
# 2. CA material backup
# ---------------------------------------------------------------------------
info "Starting CA material backup..."
CA_DIR="${CONFIG_DIR}/ca"

if [[ -d "${CA_DIR}" ]]; then
    CA_FILE="${BACKUP_DIR}/patch_manager_ca_${TIMESTAMP}.tar.gz.gpg"
    CA_TAR=$(mktemp /tmp/pm_ca_backup_XXXXXX.tar.gz)

    tar -czf "${CA_TAR}" -C "$(dirname "${CA_DIR}")" ca/ 2>/dev/null

    if [[ -n "${GPG_RECIPIENT}" ]]; then
        # Encrypt with GPG — CA key is the most critical secret
        if gpg --batch --encrypt --recipient "${GPG_RECIPIENT}" --output "${CA_FILE}" "${CA_TAR}" 2>/dev/null; then
            chmod 600 "${CA_FILE}"
            CA_SIZE=$(du -h "${CA_FILE}" | cut -f1)
            info "CA backup (encrypted): ${CA_FILE} (${CA_SIZE})"
        else
            error "CA backup GPG encryption FAILED."
            BACKUP_SUCCESS=false
        fi
        rm -f "${CA_TAR}"
    else
        # No GPG recipient — store unencrypted with strict permissions
        warn "GPG_RECIPIENT not set. CA backup stored UNENCRYPTED with strict permissions."
        CA_FILE_UNENCRYPTED="${BACKUP_DIR}/patch_manager_ca_${TIMESTAMP}.tar.gz"
        mv "${CA_TAR}" "${CA_FILE_UNENCRYPTED}"
        chmod 600 "${CA_FILE_UNENCRYPTED}"
        chown root:root "${CA_FILE_UNENCRYPTED}"
        CA_SIZE=$(du -h "${CA_FILE_UNENCRYPTED}" | cut -f1)
        info "CA backup (unencrypted): ${CA_FILE_UNENCRYPTED} (${CA_SIZE})"
    fi
else
    warn "CA directory not found at ${CA_DIR}, skipping CA backup."
fi

# ---------------------------------------------------------------------------
# 3. Config backup (excluding secrets unless encrypted destination)
# ---------------------------------------------------------------------------
info "Starting config backup..."
CONFIG_FILE="${BACKUP_DIR}/patch_manager_config_${TIMESTAMP}.tar.gz"
CONFIG_FILE_GPG="${BACKUP_DIR}/patch_manager_config_${TIMESTAMP}.tar.gz.gpg"
CONFIG_TAR=$(mktemp /tmp/pm_config_backup_XXXXXX.tar.gz)

# Build file list — always include non-secret config files
CONFIG_FILES=(
    "${CONFIG_DIR}/config.toml"
    "${CONFIG_DIR}/jwt/verify.pem"
)

# Include TLS cert (public) if present
if [[ -f "${CONFIG_DIR}/tls/tls.crt" ]]; then
    CONFIG_FILES+=("${CONFIG_DIR}/tls/tls.crt")
fi

# Build tar from existing files only
EXISTING_FILES=()
for f in "${CONFIG_FILES[@]}"; do
    [[ -f "${f}" ]] && EXISTING_FILES+=("${f}")
done

if [[ ${#EXISTING_FILES[@]} -gt 0 ]]; then
    tar -czf "${CONFIG_TAR}" "${EXISTING_FILES[@]}" 2>/dev/null

    # If GPG_RECIPIENT is set, include secrets in the backup (encrypted)
    if [[ -n "${GPG_RECIPIENT}" ]]; then
        # Add secret files to a separate encrypted archive
        SECRET_FILES=()
        [[ -f "${CONFIG_DIR}/jwt/signing.pem" ]] && SECRET_FILES+=("${CONFIG_DIR}/jwt/signing.pem")
        [[ -f "${CONFIG_DIR}/tls/tls.key" ]] && SECRET_FILES+=("${CONFIG_DIR}/tls/tls.key")
        [[ -f "${CONFIG_DIR}/config.toml" ]] && SECRET_FILES+=("${CONFIG_DIR}/config.toml")  # May contain DB URL

        if [[ ${#SECRET_FILES[@]} -gt 0 ]]; then
            # Re-create tar with secrets included
            ALL_FILES=("${EXISTING_FILES[@]}" "${SECRET_FILES[@]}")
            # Deduplicate
            ALL_FILES_UNIQUE=( $(echo "${ALL_FILES[@]}" | tr ' ' '\n' | sort -u) )
            rm -f "${CONFIG_TAR}"
            tar -czf "${CONFIG_TAR}" "${ALL_FILES_UNIQUE[@]}" 2>/dev/null
        fi

        gpg --batch --encrypt --recipient "${GPG_RECIPIENT}" --output "${CONFIG_FILE_GPG}" "${CONFIG_TAR}" 2>/dev/null
        chmod 600 "${CONFIG_FILE_GPG}"
        rm -f "${CONFIG_TAR}"
        CFG_SIZE=$(du -h "${CONFIG_FILE_GPG}" | cut -f1)
        info "Config backup (encrypted, secrets included): ${CONFIG_FILE_GPG} (${CFG_SIZE})"
    else
        # No encryption — secrets excluded, only public config
        mv "${CONFIG_TAR}" "${CONFIG_FILE}"
        chmod 600 "${CONFIG_FILE}"
        chown root:root "${CONFIG_FILE}"
        CFG_SIZE=$(du -h "${CONFIG_FILE}" | cut -f1)
        info "Config backup (secrets excluded): ${CONFIG_FILE} (${CFG_SIZE})"
    fi
else
    warn "No config files found, skipping config backup."
fi

# ---------------------------------------------------------------------------
# 4. Retention cleanup
# ---------------------------------------------------------------------------
info "Cleaning up backups older than ${RETENTION_DAYS} days..."
DELETED_COUNT=0
for pattern in "patch_manager_db_" "patch_manager_ca_" "patch_manager_config_"; do
    while IFS= read -r -d '' old_file; do
        rm -f "${old_file}"
        ((DELETED_COUNT++)) || true
    done < <(find "${BACKUP_DIR}" -name "${pattern}*" -mtime +"${RETENTION_DAYS}" -print0)
done
info "Removed ${DELETED_COUNT} expired backup(s)."

# ---------------------------------------------------------------------------
# 5. Summary
# ---------------------------------------------------------------------------
if [[ "${BACKUP_SUCCESS}" == true ]]; then
    info "=== Backup completed successfully ==="
    info "Backup directory: ${BACKUP_DIR}"
    info "Total size: $(du -sh "${BACKUP_DIR}" | cut -f1)"
    info "RPO target: 24 hours (nightly schedule)"
    exit 0
else
    error "=== Backup completed WITH ERRORS ==="
    exit 1
fi
