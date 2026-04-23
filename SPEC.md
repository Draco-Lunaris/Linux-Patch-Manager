# Linux_Patch_Manager - Specification Document

## Project Overview
**Title:** Linux_Patch_Manager
**Description:** Enterprise class secure web based management interface for controlling patching and updates on Linux servers and workstations
**Version:** 0.0.1
**Status:** Draft

## Scope

**In Scope:**
- Centralized dashboard for fleet-wide patch status monitoring (5 min health polling, 30 min patch polling, on-demand refresh) with visual alerts for unhealthy/unreachable agents
- Multi-distribution support (Debian/Ubuntu, RHEL/CentOS/Fedora, Alpine, Arch)
- Batch patch operations across multiple hosts
- Maintenance window scheduling (per-device, daily/weekly/monthly recurring + one-time) with immediate-apply override
- Compliance reporting and patch status dashboards (compliance, patch history, vulnerability exposure, audit trail — exportable as CSV and PDF)
- User management with RBAC
- Secure mTLS communication with Linux Patch API agents
- Real-time job status via WebSocket relay
- Host registration (manual FQDN/IP + on-demand CIDR auto-discover)
- Static group-based device organization with group-scoped operator access
- Email notifications (optional, disabled by default)

**Out of Scope:**
- Configuration management (Ansible/Puppet/Chef territory)
- OS provisioning, imaging, or bootstrapping
- Vulnerability scanning (manager consumes CVE data from agents, does not scan)
- Mobile UI / native apps
- Automated certificate distribution to agents
- Agent installation/management (separate concern)
- Webhook/Slack/other external notification integrations
- Multi-instance clustering / automatic horizontal scaling

## Objectives

**Primary Objective:** Provide a centralized web interface to monitor and control patch operations across a fleet of Linux hosts via the Linux Patch API.

**Key Goals:**
- Fleet-wide visibility into patch status and compliance
- Zero-friction patch deployment via maintenance windows
- Secure-by-design architecture (Rust core, mTLS, MFA)
- Single-instance simplicity supporting up to 2,500 managed hosts

## Constraints

**Deployment:**
- Single bare metal/VM host running Ubuntu 24.04
- Systemd service management
- Internal network access only (same network as managed agents)

**Technical:**
- Backend: Rust with Axum framework, Tokio async runtime
- Frontend: React + TypeScript SPA
- Database: PostgreSQL with SQLx for type-safe queries
- Real-time: Axum native WebSocket support for agent-to-browser relay
- Single-instance design (manual horizontal scaling by dividing clients between multiple Patch Manager hosts if needed)
- Fleet capacity: ~500 typical, up to 2,500 hosts

**Security:**
- Combination authentication: local accounts + Azure SSO
- MFA required for all users (TOTP or WebAuthn)
- Azure SSO users may use Azure's built-in MFA
- mTLS for all agent communication
- HTTPS for web UI
- Role-based access control:
  - **Admin**: Full access to manage all aspects of Linux Patch Manager
  - **Operator**: Can add/remove clients, manage schedules and patches only for devices in their group memberships
  - Groups are static; devices and operators can belong to multiple groups
  - Ungrouped devices can be managed by any operator or admin

## Architecture Overview

Management plane web application communicating with Linux Patch API agents on each managed host.

```
┌─────────────────────────────┐
│    Linux Patch Manager      │  ← Web UI (this project)
│     (Management Plane)      │     Rust/Axum + React/TS
│     PostgreSQL + WebSocket  │
└──────────────┬──────────────┘
               │  mTLS / REST API
        ┌──────┼──────┐
        ▼      ▼      ▼
   ┌──────┐┌──────┐┌──────┐
   │ Host ││ Host ││ Host │  ← Linux Patch API agents
   │  A   ││  B   ││  C   │     (up to 2,500)
   └──────┘└──────┘└──────┘
```

## API Integration

**Upstream Dependency:** [Linux Patch API](https://gitea.moon-dragon.us/echo/linux_patch_api)
- All managed device access uses the Linux Patch API
- mTLS certificate-based authentication to agents
- Hybrid sync/async operation model (sync for queries, async jobs for patch operations)
- WebSocket streaming for real-time job status from agents
- Base path: `/api/v1/`, Port: 12443, TLS 1.3 only

## Certificate Management

- Internal CA managed by Patch Manager, installed on the same host
- Patch Manager issues and renews client certificates for mTLS communication
- Certificate distribution to managed target clients is manual (server administrators responsible)
- Patch Manager has no direct permissions on managed clients

## User Interface

### Pages/Views

1. **Dashboard** — Fleet overview: patch compliance %, host health summary, pending patches, upcoming maintenance windows. Includes root CA certificate download icon.
2. **Hosts** — List of all managed hosts with filtering by group, health status, OS, patch status
3. **Host Detail** — Single host view: system info, installed packages, available patches, job history, maintenance window config. Includes host-specific mTLS certificate download icon.
4. **Patch Deployment** — Select hosts → review available patches → deploy (queue for window or apply now)
5. **Jobs** — Real-time job monitoring with WebSocket status updates
6. **Maintenance Windows** — Create/edit recurring and one-time windows per device
7. **Groups** — Manage static groups, assign hosts and operators
8. **Reports** — Generate and export compliance, patch history, vulnerability, audit reports (CSV and PDF)
9. **Users** — Manage local accounts, MFA setup, group assignments
10. **Certificates** — View/manage internal CA, issue/renew client certs
11. **Settings** — System configuration, Azure SSO setup, polling intervals

## Error Handling

**Agent Communication Failures:**
- Mark host as unhealthy in dashboard
- Retry with exponential backoff (3 retries, max 30 minutes between retries)
- Continue processing other hosts without blocking

**Patch Job Failures:**
- Auto-retry failed patch jobs once if still within the maintenance window
- If retry fails or window has closed, surface failure prominently to operators

**Batch Operations with Partial Failures:**
- Auto-retry failed hosts once
- If retry fails, report which hosts failed and let operator decide next steps
- Successful hosts proceed normally regardless of failures

## Assumptions

- Patch Manager host has network connectivity to all managed agents
- Linux Patch API agent is installed and running on each managed host
- Server administrators manually distribute mTLS and root certificates to managed clients
- PostgreSQL is available on the Patch Manager host

## Dependencies

- Linux Patch API (upstream agent on each managed host)
- PostgreSQL
- Internal CA for mTLS certificates
- Azure AD (optional, for SSO)

## Audit Logging

**Captured Events:**
- All user login/logout events (success and failure)
- All patch operations (who triggered, which hosts, what patches, queue vs immediate)
- All host registration/removal events
- All group membership changes (hosts and users)
- All certificate operations (issue, renew, download)
- All maintenance window changes
- All configuration changes

**Retention:** 6 months
