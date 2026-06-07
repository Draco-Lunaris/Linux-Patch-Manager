#!/bin/bash
set -e

# =============================================================================
# Linux Patch Manager — Docker Entrypoint
# =============================================================================
# Handles first-run: wait for DB, run migrations, generate admin password,
# start pm-web and pm-worker services.
# =============================================================================

MIGRATION_DIR="/usr/share/patch-manager/migrations"
CONFIG_DIR="/etc/patch-manager"
ADMIN_PASSWORD_FILE="/etc/patch-manager/admin-password.txt"

# ---------------------------------------------------------------------------
# Parse DATABASE_URL into PG* env vars for psql compatibility
# ---------------------------------------------------------------------------
parse_database_url() {
    # DATABASE_URL format: postgres://user:password@host:port/dbname
    local url="${DATABASE_URL}"

    # Extract components
    DB_PASS=$(echo "$url" | sed -n 's|postgres://[^:]*:\([^@]*\)@.*|\1|p')
    DB_HOST=$(echo "$url" | sed -n 's|.*@\([^:/]*\).*|\1|p')
    DB_PORT=$(echo "$url" | sed -n 's|.*:\([0-9]*\)/.*|\1|p')
    DB_USER=$(echo "$url" | sed -n 's|postgres://\([^:]*\):.*|\1|p')
    DB_NAME=$(echo "$url" | sed -n 's|.*/\([^?]*\).*|\1|p')

    # Default port
    DB_PORT="${DB_PORT:-5432}"

    export PGHOST="${DB_HOST}"
    export PGPORT="${DB_PORT}"
    export PGUSER="${DB_USER}"
    export PGPASSWORD="${DB_PASS}"
    export PGDATABASE="${DB_NAME}"
}

# ---------------------------------------------------------------------------
# Wait for PostgreSQL to be ready
# ---------------------------------------------------------------------------
wait_for_db() {
    echo "[entrypoint] Waiting for PostgreSQL at ${PGHOST}:${DB_PORT}..."
    local retries=60
    local delay=2
    local i
    for ((i = 1; i <= retries; i++)); do
        if pg_isready -q -h "${PGHOST}" -p "${DB_PORT}" -U "${DB_USER}" 2>/dev/null; then
            echo "[entrypoint] PostgreSQL is ready."
            return 0
        fi
        echo "[entrypoint] PostgreSQL not ready (attempt ${i}/${retries}), waiting ${delay}s..."
        sleep "${delay}"
    done
    echo "[entrypoint] ERROR: PostgreSQL did not become ready after $((retries * delay)) seconds." >&2
    return 1
}

# ---------------------------------------------------------------------------
# Run database migrations (idempotent)
# ---------------------------------------------------------------------------
run_migrations() {
    echo "[entrypoint] Applying database migrations..."

    # Ensure pgcrypto extension
    psql -v ON_ERROR_STOP=1 -c "CREATE EXTENSION IF NOT EXISTS pgcrypto;" 2>/dev/null || true

    # Create migration tracking table
    psql -v ON_ERROR_STOP=1 <<'EOSQL'
CREATE TABLE IF NOT EXISTS _migrations (
    id          SERIAL PRIMARY KEY,
    filename    TEXT    NOT NULL UNIQUE,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
EOSQL

    # Handle upgrade from pre-migration-tracking versions
    local migration_count
    migration_count=$(psql -t -A -c "SELECT COUNT(*) FROM _migrations;" 2>/dev/null || echo "0")
    migration_count="${migration_count// /}"

    local tables_exist
    tables_exist=$(psql -t -A -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='users';" 2>/dev/null || echo "0")
    tables_exist="${tables_exist// /}"

    if [[ "${migration_count}" == "0" && "${tables_exist}" -gt 0 ]]; then
        echo "[entrypoint] Existing database detected — marking all shipped migrations as already applied."
        for sql_file in $(ls "${MIGRATION_DIR}"/*.sql 2>/dev/null | sort); do
            local fname
            fname=$(basename "${sql_file}")
            psql -v ON_ERROR_STOP=1 -c "INSERT INTO _migrations (filename) VALUES ('${fname}') ON CONFLICT (filename) DO NOTHING;" 2>/dev/null || true
        done
    fi

    # Apply each migration in sorted order
    local applied=0
    local skipped=0
    for sql_file in $(ls "${MIGRATION_DIR}"/*.sql 2>/dev/null | sort); do
        local fname
        fname=$(basename "${sql_file}")

        local already_applied
        already_applied=$(psql -t -A -c "SELECT COUNT(*) FROM _migrations WHERE filename='${fname}';" 2>/dev/null || echo "0")
        already_applied="${already_applied// /}"

        if [[ "${already_applied}" -gt 0 ]]; then
            skipped=$((skipped + 1))
            continue
        fi

        echo "[entrypoint]   Applying migration: ${fname}"
        if psql -v ON_ERROR_STOP=1 -f "${sql_file}"; then
            psql -v ON_ERROR_STOP=1 -c "INSERT INTO _migrations (filename) VALUES ('${fname}');" 2>/dev/null || true
            applied=$((applied + 1))
        else
            echo "[entrypoint] ERROR: Failed to apply migration: ${fname}" >&2
            return 1
        fi
    done

    if [[ "${applied}" -gt 0 ]]; then
        echo "[entrypoint] Applied ${applied} new migration(s), skipped ${skipped}."
    else
        echo "[entrypoint] All migrations up to date (${skipped} already applied)."
    fi
}

# ---------------------------------------------------------------------------
# Generate admin password on first run
# ---------------------------------------------------------------------------
generate_admin_password() {
    echo "[entrypoint] Checking admin password status..."

    # Generate a random 24-character password
    local admin_password
    admin_password=$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9!@#%^&*' | head -c 24)

    # Hash with argon2 (PHC format)
    local password_hash
    password_hash=$(echo -n "${admin_password}" | argon2 salt -id -t 3 -m 65536 -p 1 -l 32 -e)

    # Update admin user — only if placeholder hash is still present
    # The placeholder starts with: $argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAA
    # Using single-quoted variable to preserve $ signs in the SQL LIKE pattern
    local placeholder_pattern
    placeholder_pattern='$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAA%'

    local updated
    updated=$(psql -t -A -c \
        "UPDATE users SET password_hash = '${password_hash}', force_password_reset = TRUE \
         WHERE username = 'admin' AND password_hash LIKE '${placeholder_pattern}' \
         RETURNING id;" 2>/dev/null || echo "")

    if [[ -n "${updated}" ]]; then
        echo "${admin_password}" > "${ADMIN_PASSWORD_FILE}"
        chmod 600 "${ADMIN_PASSWORD_FILE}"
        chown root:root "${ADMIN_PASSWORD_FILE}"

        echo ""
        echo "============================================="
        echo "  Linux Patch Manager — Admin Credentials"
        echo "============================================="
        echo "  Username: admin"
        echo "  Password: ${admin_password}"
        echo ""
        echo "  IMPORTANT: Save this password! It will not be shown again."
        echo "  Password also saved to: ${ADMIN_PASSWORD_FILE}"
        echo "============================================="
        echo ""
    else
        echo "[entrypoint] Admin password already set (not a fresh install)."
    fi
}

# ---------------------------------------------------------------------------
# Generate JWT keys if not present
# ---------------------------------------------------------------------------
generate_jwt_keys() {
    if [[ ! -f "${CONFIG_DIR}/jwt/signing.pem" ]]; then
        echo "[entrypoint] Generating Ed25519 JWT signing key..."
        openssl genpkey -algorithm ed25519 -out "${CONFIG_DIR}/jwt/signing.pem" 2>/dev/null
        openssl pkey -in "${CONFIG_DIR}/jwt/signing.pem" -pubout -out "${CONFIG_DIR}/jwt/verify.pem" 2>/dev/null
        chown patch-manager:patch-manager "${CONFIG_DIR}/jwt/signing.pem" "${CONFIG_DIR}/jwt/verify.pem"
        chmod 600 "${CONFIG_DIR}/jwt/signing.pem"
        chmod 644 "${CONFIG_DIR}/jwt/verify.pem"
        echo "[entrypoint] JWT keys generated."
    else
        echo "[entrypoint] JWT signing key already exists."
    fi
}

# ---------------------------------------------------------------------------
# Write config.toml if not present
# ---------------------------------------------------------------------------
write_config() {
    local config_file="${CONFIG_DIR}/config.toml"

    if [[ -f "${config_file}" ]]; then
        echo "[entrypoint] Config file already exists, not overwriting."
        return 0
    fi

    echo "[entrypoint] Writing configuration file..."
    cp /usr/share/patch-manager/config.example.toml "${config_file}"
    sed -i "s|postgres://patch_manager:CHANGEME@localhost/patch_manager|${DATABASE_URL}|" "${config_file}"
    chown patch-manager:patch-manager "${config_file}"
    chmod 640 "${config_file}"
    echo "[entrypoint] Configuration written."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "[entrypoint] Linux Patch Manager Docker entrypoint starting..."

parse_database_url
wait_for_db
run_migrations
generate_admin_password
generate_jwt_keys
write_config

echo "[entrypoint] Starting pm-web and pm-worker..."

# Start pm-worker in background
pm-worker &
WORKER_PID=$!

# Start pm-web in foreground (main process)
export PATCH_MANAGER_CONFIG="${CONFIG_DIR}/config.toml"

exec pm-web
