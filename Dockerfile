# =============================================================================
# Linux Patch Manager — Multi-stage Docker Build
# =============================================================================
# Build:  docker build -t linux-patch-manager .
# Run:    docker compose up
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Rust build
# ---------------------------------------------------------------------------
FROM rust:1.82-bookworm AS rust-builder

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libfontconfig1-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app

# Cache dependencies by building a dummy project first
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p crates/pm-web/src crates/pm-worker/src crates/pm-core/src \
    crates/pm-agent-client/src crates/pm-auth/src crates/pm-ca/src \
    crates/pm-reports/src crates/migrate-secrets/src
RUN echo 'fn main(){}' > crates/pm-web/src/main.rs \
    && echo 'fn main(){}' > crates/pm-worker/src/main.rs \
    && echo '' > crates/pm-core/src/lib.rs \
    && echo '' > crates/pm-agent-client/src/lib.rs \
    && echo '' > crates/pm-auth/src/lib.rs \
    && echo '' > crates/pm-ca/src/lib.rs \
    && echo '' > crates/pm-reports/src/lib.rs \
    && echo 'fn main(){}' > crates/migrate-secrets/src/main.rs
RUN cargo build --release 2>/dev/null || true

# Now build the real project
COPY crates/ crates/
RUN cargo build --release

# Verify binaries exist
RUN ls -la target/release/pm-web target/release/pm-worker

# Strip debug symbols
RUN strip target/release/pm-web target/release/pm-worker

# ---------------------------------------------------------------------------
# Stage 2: Frontend build
# ---------------------------------------------------------------------------
FROM node:20-bookworm-slim AS frontend-builder

WORKDIR /usr/src/app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --production=false

COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------------------
# Stage 3: Runtime
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libfontconfig1 \
    postgresql-client-16 \
    argon2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create service user
RUN useradd --system --no-create-home --shell /usr/sbin/nologin \
    --comment "Linux Patch Manager service account" patch-manager

# Create directories
RUN mkdir -p /etc/patch-manager/ca /etc/patch-manager/certs \
    /etc/patch-manager/jwt /etc/patch-manager/tls \
    /var/log/patch-manager /opt/patch-manager \
    /usr/share/patch-manager/frontend \
    /usr/share/patch-manager/migrations

# Copy binaries
COPY --from=rust-builder /usr/src/app/target/release/pm-web /usr/local/bin/pm-web
COPY --from=rust-builder /usr/src/app/target/release/pm-worker /usr/local/bin/pm-worker

# Copy frontend
COPY --from=frontend-builder /usr/src/app/frontend/dist/ /usr/share/patch-manager/frontend/

# Copy migrations
COPY migrations/ /usr/share/patch-manager/migrations/

# Copy entrypoint
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

# Copy config template
COPY config/config.example.toml /usr/share/patch-manager/config.example.toml

# Set ownership
RUN chown -R patch-manager:patch-manager \
    /etc/patch-manager /var/log/patch-manager \
    /opt/patch-manager /usr/share/patch-manager

# Expose HTTPS port
EXPOSE 443

# Volume for persistent data
VOLUME ["/etc/patch-manager", "/var/log/patch-manager", "/opt/patch-manager"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
