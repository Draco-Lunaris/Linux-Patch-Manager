# Linux Patch Manager

**Enterprise-class secure web-based management interface for controlling patching and updates on Linux servers and workstations.**

## Overview

Linux Patch Manager provides a centralized web interface to manage patching and software updates across a fleet of Linux servers and workstations. It communicates with managed devices through the [Linux Patch API](https://gitea.moon-dragon.us/echo/linux_patch_api), leveraging mTLS-secured RESTful endpoints for all operations.

## Key Features

- **Centralized Dashboard** — Monitor patch status across all managed hosts from a single interface
- **Multi-Distribution Support** — Manage Debian/Ubuntu, RHEL/CentOS/Fedora, Alpine, and Arch hosts
- **Secure by Design** — mTLS authentication, role-based access control, audit logging
- **Batch Operations** — Apply patches and updates across multiple hosts simultaneously
- **Scheduling** — Plan and schedule patch windows with approval workflows
- **Reporting** — Compliance reporting and patch status dashboards

## Architecture

Linux Patch Manager is a web application that acts as a management plane, communicating with the Linux Patch API agent running on each managed host.

```
┌─────────────────────┐
│  Linux Patch Manager │  ← Web UI (this project)
│   (Management Plane) │
└──────────┬──────────┘
           │  mTLS / REST API
    ┌──────┼──────┐
    ▼      ▼      ▼
┌──────┐┌──────┐┌──────┐
│ Host ││ Host ││ Host │  ← Linux Patch API agents
│  A   ││  B   ││  C   │
└──────┘└──────┘└──────┘
```

## Documentation

| Document | Description |
|----------|-------------|
| [SPEC.md](SPEC.md) | Full project specification |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architecture and design decisions |
| [REQUIREMENTS.md](REQUIREMENTS.md) | Functional and non-functional requirements |

## Related Projects

- **[Linux Patch API](https://gitea.moon-dragon.us/echo/linux_patch_api)** — The API agent that runs on each managed host

## License

Private — All rights reserved.
# CI Test Run - $(date)
