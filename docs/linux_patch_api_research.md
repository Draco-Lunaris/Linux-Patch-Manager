# Linux Patch API — Comprehensive Research Summary

*Generated: 2026-04-28*
*Sources: Extracted .deb package (v1.0.0-1), pm-agent-client crate, linux_patch_manager project docs*

---

## 1. What the Project Is and Does

**Linux Patch API** is a secure, mTLS-authenticated REST API service that runs on each managed Linux host. It is the **agent-side counterpart** to the Linux Patch Manager (the management plane). The agent exposes endpoints for:

- **Health monitoring** — liveness checks and uptime reporting
- **System information** — hostname, OS, kernel, architecture, pending reboot status
- **Package listing** — installed and upgradable packages with CVE associations
- **Patch discovery** — available patches with severity, CVE data, and reboot requirements
- **Patch application** — async job-based patch deployment with optional reboot
- **Job status tracking** — polling async job progress and output
- **Job rollback** — reverting a previously applied patch job

The agent is designed for **fleet management at scale** (up to 2,500 hosts per Manager instance) with:
- Mutual TLS (mTLS) authentication — TLS 1.3 only
- IP whitelist enforcement
- Asynchronous job processing for long-running operations
- Comprehensive audit logging
- Systemd integration with security hardening

### Architecture Position

```
+-----------------------------+
|    Linux Patch Manager      |  <- Management plane (separate project)
|     (Rust/Axum + React/TS)  |
|     PostgreSQL + WebSocket  |
+--------------+--------------+
               |
               |  mTLS / REST + WSS (TLS 1.3, port 12443)
       +-------+-------+
       v       v       v
   +------+ +------+ +------+
   | Host | | Host | | Host |  <- Linux Patch API agents (this project)
   |  A   | |  B   | |  C   |     (up to 2,500)
   +------+ +------+ +------+
```

---

## 2. How to Build and Install

### From Pre-built .deb Package (Recommended)

Download the release package:

```bash
# Replace v0.0.2 with the latest release tag
wget https://github.com/Draco-Lunaris/Linux-Patch-Api/releases/download/v0.0.2/linux-patch-api_1.0.0-1_amd64.deb
sudo apt install ./linux-patch-api_1.0.0-1_amd64.deb
```

**Package dependencies** (from DEBIAN/control):
- `systemd`
- `libsystemd0`
- `libc6 (>= 2.39)`
- `libgcc-s1 (>= 4.2)`

**Installed files:**
- `/usr/bin/linux-patch-api` — the binary
- `/etc/linux_patch_api/config.yaml` — configuration file
- `/etc/linux_patch_api/whitelist.yaml` — IP whitelist
- `/lib/systemd/system/linux-patch-api.service` — systemd unit

**Post-install actions** (automatic via postinst script):
1. Copies example configs if they don't exist
2. Sets ownership to `linux-patch-api:linux-patch-api`
3. Sets file permissions (640 on config/whitelist)
4. Reloads systemd daemon
5. Enables the service (does NOT auto-start — admin must configure first)

### Installation Steps Summary

```bash
# 1. Install the package
sudo apt install ./linux-patch-api_1.0.0-1_amd64.deb

# 2. Configure /etc/linux_patch_api/config.yaml with your settings
sudo nano /etc/linux_patch_api/config.yaml

# 3. Place TLS certificates in /etc/linux_patch_api/certs/
#    Required: ca.pem, server.pem, server.key
sudo mkdir -p /etc/linux_patch_api/certs
sudo cp ca.pem server.pem server.key /etc/linux_patch_api/certs/

# 4. Configure IP whitelist in /etc/linux_patch_api/whitelist.yaml
sudo nano /etc/linux_patch_api/whitelist.yaml

# 5. Start the service
sudo systemctl start linux-patch-api
sudo systemctl status linux-patch-api
```

---

## 3. Configuration Requirements

### config.yaml — Full Reference

```yaml
# Server Configuration
server:
  port: 12443                    # HTTPS/mTLS port (default: 12443)
  bind: "0.0.0.0"                # Bind address
  timeout_seconds: 30            # Request timeout

# TLS/mTLS Configuration
tls:
  enabled: true                  # TLS is mandatory
  port: 12443                    # TLS port
  ca_cert: "/etc/linux_patch_api/certs/ca.pem"       # Internal CA certificate
  server_cert: "/etc/linux_patch_api/certs/server.pem"  # Server certificate
  server_key: "/etc/linux_patch_api/certs/server.key"  # Server private key
  min_tls_version: "1.3"         # TLS 1.3 enforced

# Job Configuration
jobs:
  max_concurrent: 5              # Maximum concurrent async jobs
  timeout_minutes: 30            # Job timeout
  storage_path: "/var/lib/linux_patch_api/jobs"  # Job state directory

# Logging Configuration
logging:
  level: "info"                  # trace, debug, info, warn, error
  journal_enabled: true          # systemd journal logging
  syslog_enabled: false          # syslog (optional)
  # syslog_server: "udp://localhost:514"
  file_path: "/var/log/linux_patch_api/audit.log"  # Audit log file
  retention_days: 30             # Log retention

# IP Whitelist Configuration
whitelist:
  path: "/etc/linux_patch_api/whitelist.yaml"
  # Entries: individual IPs, CIDR subnets, or hostnames

# Package Manager Backend
package_manager:
  backend: "auto"               # auto, apt, dnf, yum, apk, pacman
```

### whitelist.yaml — IP Whitelist

```yaml
# Block all by default - only listed IPs/CIDRs/hostnames can access the API
entries:
  - "192.168.1.0/24"      # Management network
  - "10.0.0.50"          # Specific admin workstation
  # - "admin-server.internal"  # Hostname (resolved at startup)
```

### Required Directories and Permissions

| Path | Purpose | Owner | Mode |
|------|---------|-------|------|
| `/etc/linux_patch_api/` | Configuration | linux-patch-api:linux-patch-api | 750 |
| `/etc/linux_patch_api/config.yaml` | Main config | linux-patch-api:linux-patch-api | 640 |
| `/etc/linux_patch_api/whitelist.yaml` | IP whitelist | linux-patch-api:linux-patch-api | 640 |
| `/etc/linux_patch_api/certs/` | TLS certificates | — | 700 |
| `/var/lib/linux_patch_api/jobs/` | Job state | linux-patch-api:linux-patch-api | 750 |
| `/var/log/linux_patch_api/` | Audit logs | linux-patch-api:linux-patch-api | 750 |

### Required TLS Certificates

The agent requires three PEM files in `/etc/linux_patch_api/certs/`:

1. **ca.pem** — Internal CA certificate (same CA used by Patch Manager for mTLS)
2. **server.pem** — Server certificate issued by the internal CA
3. **server.key** — Server private key (must be 0600 permissions)

These are distributed manually by server administrators (not automated by the Manager).

---

## 4. How It Connects to the Patch Manager Server

### Connection Model

- **Protocol**: HTTPS with mutual TLS (mTLS)
- **TLS Version**: 1.3 only (enforced, no fallback)
- **Port**: 12443
- **Base Path**: `/api/v1/`
- **Direction**: Manager initiates connections to agents (agents are passive servers)
- **Authentication**: mTLS with client certificates issued by the Patch Manager's internal CA

### mTLS Configuration (Manager Side)

The Patch Manager's `config.example.toml` specifies:

```toml
[security]
# mTLS client certificate for agent communication
agent_client_cert_path = "/etc/patch-manager/certs/client.crt"
agent_client_key_path  = "/etc/patch-manager/certs/client.key"

# Internal CA certificate and private key
ca_cert_path = "/etc/patch-manager/ca/ca.crt"
ca_key_path  = "/etc/patch-manager/ca/ca.key"
```

The `pm-agent-client` crate constructs the mTLS client with:
- `rustls` TLS backend (no OpenSSL dependency)
- Built-in system root CAs **disabled** — only the internal CA is trusted
- TLS 1.3 minimum version enforced
- Client identity (cert + key) presented during handshake
- 30-second request timeout

### API Endpoints

All endpoints are prefixed with `/api/v1/`. The Manager communicates with agents via the `AgentClient` struct.

| Method | Endpoint | Description | Request | Response Type |
|--------|----------|-------------|---------|---------------|
| GET | `/api/v1/health` | Agent liveness check | — | `HealthData` |
| GET | `/api/v1/system/info` | Host system information | — | `SystemInfoData` |
| GET | `/api/v1/packages?status=upgradable` | List upgradable packages | Query param | `PackagesData` |
| GET | `/api/v1/patches` | List available patches | — | `PatchesData` |
| POST | `/api/v1/patches/apply` | Trigger patch application | `ApplyPatchesRequest` | `ApplyPatchesResponse` |
| GET | `/api/v1/jobs/{id}` | Poll async job status | Path param | `AgentJobStatus` |
| POST | `/api/v1/jobs/{id}/rollback` | Rollback a patch job | Path param | `RollbackResponse` |

### Response Envelope

All agent responses use a standard envelope:

```json
{
  "success": true,
  "request_id": "uuid-v4",
  "timestamp": "2026-04-28T12:00:00Z",
  "data": { ... },
  "error": null
}
```

On error:

```json
{
  "success": false,
  "request_id": "uuid-v4",
  "timestamp": "2026-04-28T12:00:00Z",
  "data": null,
  "error": {
    "code": "INTERNAL_ERROR",
    "message": "Description",
    "details": null,
    "retryable": false
  }
}
```

### Response Type Details

**HealthData**
```json
{
  "status": "ok",           // "ok" or "degraded"
  "uptime_seconds": 86400,
  "version": "1.0.0"
}
```

**SystemInfoData**
```json
{
  "hostname": "web-server-01",
  "os": "Ubuntu",
  "os_version": "24.04",
  "kernel": "6.8.0-45-generic",
  "architecture": "x86_64",
  "last_update_check": "2026-04-28T10:00:00Z",
  "last_update_apply": "2026-04-27T02:00:00Z",
  "pending_reboot": false
}
```

**PackagesData**
```json
{
  "packages": [
    {
      "name": "openssl",
      "version": "3.0.13-0ubuntu3",
      "status": "upgradable",
      "upgradable": true,
      "latest_version": "3.0.13-0ubuntu3.1",
      "description": "Secure Sockets Layer toolkit",
      "cve_ids": ["CVE-2024-1234"]
    }
  ],
  "total": 42
}
```

**PatchesData**
```json
{
  "patches": [
    {
      "name": "openssl",
      "current_version": "3.0.13-0ubuntu3",
      "available_version": "3.0.13-0ubuntu3.1",
      "severity": "critical",
      "description": "Security update for OpenSSL",
      "cve_ids": ["CVE-2024-1234"],
      "requires_reboot": false
    }
  ],
  "total": 15,
  "security_updates": 3,
  "requires_reboot": true
}
```

**ApplyPatchesRequest**
```json
{
  "packages": ["openssl", "nginx"],  // Empty = apply all
  "allow_reboot": true
}
```

**ApplyPatchesResponse**
```json
{
  "job_id": "abc-123-def",
  "status": "running"   // "running" or "queued"
}
```

**AgentJobStatus**
```json
{
  "job_id": "abc-123-def",
  "status": "running",     // "running", "succeeded", "failed", "cancelled"
  "progress_percent": 75,
  "output": "Applying openssl...",
  "error": null,
  "started_at": "2026-04-28T12:00:00Z",
  "completed_at": null
}
```

**RollbackResponse**
```json
{
  "job_id": "abc-123-def",
  "status": "running"
}
```

### Polling and Communication Patterns

The Patch Manager communicates with agents on two schedules:

1. **Health polling** — every 5 minutes (configurable via `health_poll_interval_secs`)
2. **Patch data polling** — every 30 minutes (configurable via `patch_poll_interval_secs`)
3. **On-demand refresh** — triggered by operator from the UI
4. **Patch deployment** — triggered by operator, either queued for maintenance window or immediate
5. **Job status** — polled via `GET /api/v1/jobs/{id}` or streamed via WebSocket

The Manager uses exponential backoff retry (3 retries, max 30 minutes) for failed agent communications.

---

## 5. Setup Scripts and Systemd Units

### Agent Systemd Unit (linux-patch-api.service)

```ini
[Unit]
Description=Linux Patch API - Secure Remote Package Management
Documentation=man:linux-patch-api(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/linux-patch-api --config /etc/linux_patch_api/config.yaml
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s

# Process management
RuntimeDirectory=linux-patch-api
RuntimeDirectoryMode=0755

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/linux_patch_api /var/log/linux_patch_api
PrivateTmp=true
PrivateDevices=true
ProtectHostname=true
ProtectClock=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=false
RestrictRealtime=true
RestrictSUIDSGID=true
RemoveIPC=true

# System call filtering
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# Environment
Environment="RUST_BACKTRACE=1"
Environment="RUST_LOG=info"

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=linux-patch-api
SyslogFacility=daemon
SyslogLevel=info

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

Key systemd hardening features:
- `Type=notify` — service notifies systemd when ready
- `ProtectSystem=strict` — read-only filesystem except explicit write paths
- `NoNewPrivileges=true` — prevents privilege escalation
- `SystemCallFilter=@system-service` — whitelist-only syscall filtering
- `PrivateTmp`, `PrivateDevices`, `ProtectKernel*` — kernel resource isolation

### Manager Systemd Units

**patch-manager.target** — groups both services:
```ini
[Unit]
Description=Linux Patch Manager — Service Target
Wants=patch-manager-web.service patch-manager-worker.service

[Install]
WantedBy=multi-user.target
```

**patch-manager-web.service** — Axum web server:
- Binary: `/usr/local/bin/pm-web`
- Config: `/etc/patch-manager/config.toml`
- Runs as `patch-manager` user
- Requires PostgreSQL
- `AmbientCapabilities=CAP_NET_BIND_SERVICE` for port 443
- Restart: always, 5s delay

**patch-manager-worker.service** — Background worker:
- Binary: `/usr/local/bin/pm-worker`
- Config: `/etc/patch-manager/config.toml`
- Runs as `patch-manager` user
- Requires PostgreSQL, wants pm-web
- Restart: always, 10s delay
- Longer stop timeout (120s) for job draining

### Manager Setup Script (setup.sh)

The `scripts/setup.sh` automates initial host setup:

1. Creates `patch-manager` service user/group
2. Creates directory structure (`/etc/patch-manager/{ca,certs,jwt,tls}`, `/var/log/patch-manager`, `/opt/patch-manager`, `/usr/share/patch-manager/frontend`, `/var/backups/patch-manager`)
3. Installs PostgreSQL 16 if not present
4. Creates database and user with random password
5. Writes config.toml with database URL
6. Generates Ed25519 JWT signing/verification keys
7. Generates self-signed TLS certificate (ECDSA P-256, valid 365 days, SAN for hostname + localhost)
8. Installs systemd units
9. Installs binaries and frontend assets
10. Runs database migrations

---

## Appendix: Package Manager Backend Support

The agent's `package_manager.backend` config supports:

| Value | Distribution | Package Manager |
|-------|-------------|-----------------|
| `apt` | Debian, Ubuntu | APT |
| `dnf` | RHEL 8+, Fedora | DNF |
| `yum` | CentOS 7, older RHEL | YUM |
| `apk` | Alpine | APK |
| `pacman` | Arch Linux | Pacman |
| `auto` | Auto-detected | Detected at runtime |

---

## Appendix: Certificate Distribution Model

1. Patch Manager runs an **internal CA** on the same host
2. The CA issues:
   - Server certificates for the web UI
   - Client certificates for mTLS communication with agents
   - The CA certificate itself is distributed to agents
3. Agent certificates are **manually distributed** by server administrators
4. The Patch Manager has **no direct permissions** on managed clients
5. Certificate renewal is handled by the Patch Manager; physical distribution is manual

---

## Appendix: Error Handling

- **Agent unreachable**: Manager marks host as unhealthy, retries with exponential backoff (3 retries, max 30 min between)
- **Patch job failure**: Auto-retry once if within maintenance window, then surface to operator
- **Batch partial failure**: Auto-retry failed hosts once, report remaining failures
- **Agent error responses**: Structured `AgentErrorBody` with `code`, `message`, `details`, `retryable` flag
