# Security Policy

## Supported Versions

Only the **latest release** is currently supported with security updates.

| Version | Supported |
|---------|----------|
| Latest  | ✅       |
| Older   | ❌       |

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub Issues.**

Instead, use GitHub's private vulnerability reporting:

👉 [Report a vulnerability for Linux-Patch-Manager](https://github.com/Draco-Lunaris/Linux-Patch-Manager/security/advisories/new)

This allows us to coordinate a fix before public disclosure.

### Response Timeline

- **Acknowledgment** within 48 hours
- **Initial assessment** within 7 days
- **Ongoing updates** on remediation progress

## Disclosure Policy

We follow **coordinated disclosure**:

- We ask for **90 days** before public disclosure of a vulnerability
- Security advisories are published via [GitHub Security Advisories](https://github.com/Draco-Lunaris/Linux-Patch-Manager/security/advisories)
- We will work with you to determine an appropriate disclosure timeline when a fix requires more time

## Security Best Practices

This project is a security tool — we hold ourselves to a high standard:

- **Signed commits**: All commits must be signed (SSH signing)
- **CI enforcement**: All PRs require passing CI checks (fmt, clippy, test, audit, build)
- **Dependency auditing**: `cargo audit` runs in CI to catch known vulnerabilities

## Enrollment PKI Design Decisions

### Server-Generated Keys vs CSR-Based Enrollment

Currently, the server generates the agent's private key during enrollment approval and
transmits it over the mTLS-secured polling endpoint. This approach was chosen for
initial implementation simplicity — the agent polls a single endpoint and receives a
complete PKI bundle without an extra round-trip.

**Mitigations in place:**
- The PKI bundle is stored in an in-memory cache with single-retrieval semantics —
  it can only be fetched once and is atomically removed on retrieval.
- A 10-minute TTL ensures the bundle expires even if never retrieved.
- The raw polling token is never logged; only its SHA-256 hash is stored.

**Future direction:** A CSR-based enrollment flow should replace server-generated keys.
Under that model, the agent generates its own key pair locally and submits a Certificate
Signing Request, eliminating the need for the server to ever hold or transmit the agent's
private key. This significantly reduces the attack surface.

See: [Issue #9](https://github.com/Draco-Lunaris/Linux-Patch-Manager/issues/9)

## Credit

Contributors who responsibly report vulnerabilities will be credited in the corresponding GitHub Security Advisory.
