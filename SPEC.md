# Manager-Agent Interface Specification

**Version:** 2.0.0
**Date:** 2026-06-29
**Status:** Active
**Repository:** linux-patch-manager (canonical)

---

## 1. Purpose

This document defines the contract between the Linux Patch Manager and the Linux Patch API agent. Both components must implement this specification to ensure interoperability. Any change to this spec requires coordinated version bumps in both repositories.

---

## 2. Enrollment Protocol

### 2.1 Agent → Manager: Enrollment Request

```
POST /api/v1/enroll
Content-Type: application/json

{
  "machine_id": "<unique-machine-id>",
  "fqdn": "<fully-qualified-domain-name>",
  "ip_address": "<ip-address>",
  "os_details": {
    "os": "<os-family>",
    "name": "<os-name>",
    "os_version": "<version>",
    "architecture": "<arch>"
  },
  "hostname": "<optional-hostname>"
}
```

### 2.2 Manager → Agent: Enrollment Status

```
GET /api/v1/enroll/status/{token}

Response (pending):
HTTP 200
{
  "status": "pending"
}

Response (approved):
HTTP 200
{
  "status": "approved",
  "pki": {
    "ca_crt": "<pem>",
    "ca_chain": "<pem>",
    "server_crt": "<pem>",
    "server_key": "<pem>",
    "crl_pem": "<pem>",
    "repo_config": {
      "gpg_public_key": "<ascii-armored-gpg-key>",
      "sources_config": "<distro-specific-sources>",
      "distro_id": "<distro-identifier>",
      "keyring_path": "<path-to-install-gpg-key>"
    }
  }
}
```

### 2.3 Fallback: Repo Config Fetch

```
GET /api/v1/pki/repo-config?distro_id=<distro_id>

Response:
HTTP 200
{
  "gpg_public_key": "<ascii-armored-gpg-key>",
  "sources_config": "<distro-specific-sources>",
  "distro_id": "<distro-identifier>",
  "keyring_path": "<path-to-install-gpg-key>"
}
```

---

## 3. Self-Update API

### 3.1 Manager → Agent: Trigger Self-Update

```
POST /api/v1/system/update
Content-Type: application/json

{
  "target_version": "<version>",
  "restart": true,
  "restart_delay_seconds": 5
}

Response:
HTTP 202
{
  "status": "pending",
  "target_version": "<version>",
  "message": "Self-update initiated"
}
```

### 3.2 Agent → Manager: Self-Update Status

```
GET /api/v1/system/update/status

Response:
HTTP 200
{
  "previous_version": "<version>",
  "new_version": "<version>",
  "changed": true,
  "status": "success|failed|pending",
  "error": null,
  "at": "<iso8601-timestamp>"
}
```

---

## 4. Health Reporting

### 4.1 Agent → Manager: Health Check

```
GET /health

Response:
HTTP 200
{
  "status": "healthy",
  "version": "<agent-version>",
  "crl_status": "valid|expired|missing|invalid|null",
  "crl_age_seconds": <seconds>,
  "crl_next_update": "<iso8601-timestamp>",
  "gpg_key_status": "valid|expired|missing|revoked|null",
  "gpg_key_expires_at": "<iso8601-timestamp>"
}
```

### 4.2 Manager: Health Polling

The manager polls `GET /health` on each agent at a configurable interval. It persists the reported fields to the `hosts` table and applies CRL health aggregation rules.

---

## 5. Package Repository

### 5.1 Manager: Repo Server

The manager serves a GPG-signed package repository on port 80 (plain HTTP) at:
- `/apt/` — reprepro output (Packages, Release, InRelease)
- `/dnf/` — createrepo_c output (repodata/)
- `/apk/` — APKINDEX.tar.gz + .apk files
- `/pacman/` — repo database + .pkg.tar.zst files

No authentication is required. Package integrity is verified by the agent's native package manager via GPG signatures.

### 5.2 Manager: Package Sync

The manager pulls packages from GitHub Releases via HTTP GET to `https://api.github.com/repos/Draco-Lunaris/Linux-Patch-Api/releases`. It imports them into the local repo and signs the metadata with its own GPG key.

### 5.3 Agent: Repo Configuration

The agent provisions the GPG public key and sources config to distro-specific paths during enrollment:
- **apt:** GPG key → `/etc/apt/keyrings/lpa-repo.gpg`, sources → `/etc/apt/sources.list.d/lpa.list`
- **dnf:** GPG key → `/etc/pki/rpm-gpg/lpa-repo.gpg`, repo → `/etc/yum.repos.d/lpa.repo`
- **apk:** append URL → `/etc/apk/repositories`
- **pacman:** include file → `/etc/pacman.d/lpa-repo`

---

## 6. Version Compatibility

### 6.1 Manager → Agent: Minimum Version Check

The manager may enforce a minimum agent version. Agents below this version are flagged in the UI and may be excluded from self-update operations.

### 6.2 Agent → Manager: Required Manager Version

The agent may report a `required_manager_version` in its health response. The manager can use this to detect incompatible agents.

---

## 7. Distro Identifiers

| distro_id | Package Manager | Keyring Path |
|-----------|----------------|--------------|
| `ubuntu-24.04` | apt | `/etc/apt/keyrings/lpa-repo.gpg` |
| `ubuntu-22.04` | apt | `/etc/apt/keyrings/lpa-repo.gpg` |
| `debian-12` | apt | `/etc/apt/keyrings/lpa-repo.gpg` |
| `debian-13` | apt | `/etc/apt/keyrings/lpa-repo.gpg` |
| `fedora-40` | dnf | `/etc/pki/rpm-gpg/lpa-repo.gpg` |
| `fedora-41` | dnf | `/etc/pki/rpm-gpg/lpa-repo.gpg` |
| `almalinux-9` | dnf | `/etc/pki/rpm-gpg/lpa-repo.gpg` |
| `alpine-3.21` | apk | `/etc/apk/keys/lpa-repo.rsa.pub` |
| `alpine-3.20` | apk | `/etc/apk/keys/lpa-repo.rsa.pub` |
| `arch` | pacman | `/etc/pacman.d/gnupg/lpa-repo.gpg` |

---

## 8. Changelog

| Version | Date | Changes |
|---------|------|---------|
| 2.0.0 | 2026-06-29 | Initial spec: enrollment, self-update, health, repo, version compatibility |
