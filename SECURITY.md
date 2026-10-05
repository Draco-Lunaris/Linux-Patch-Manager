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
- **Secret scanning**: Gitleaks runs over full history on every CI run
- **Verifiable releases**: every release ships `SHA256SUMS`, a detached GPG signature
  over it, and a signed
  [build-provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds).
  Verify before installing:

  ```bash
  gpg --verify SHA256SUMS.asc SHA256SUMS
  sha256sum --check --ignore-missing SHA256SUMS
  gh attestation verify linux-patch-manager_*_amd64.deb --repo Draco-Lunaris/Linux-Patch-Manager
  ```

  The release signing key fingerprint is published below. See
  [docs/release-signing.md](docs/release-signing.md) for what each artifact proves and
  how the key is managed.

### Release Signing Key

`SHA256SUMS.asc` is signed with this key:

```
pub   ed25519 2026-10-05 [SC] [expires: 2028-10-04]
      0D5D 7A60 4EB5 CAE5 C02C  0F80 1000 E3EB E9DC 3B74
uid   Linux Patch Manager Release Signing <331325+Draco-Lunaris@users.noreply.github.com>
```

The public key is attached to each release as `release-signing-key.asc`. **Compare its
fingerprint against the value above before trusting it** — a key downloaded from the
same release as the artifact it vouches for proves nothing on its own.

```bash
gpg --import release-signing-key.asc
gpg --fingerprint 0D5D7A604EB5CAE5C02C0F801000E3EBE9DC3B74
```

This key signs release artifacts only. It is unrelated to the per-instance GPG key each
manager generates to sign the packages it serves to agents — see
[docs/gpg-key-rotation.md](docs/gpg-key-rotation.md) for that one, and
[docs/release-signing.md](docs/release-signing.md) for this one.

Releases published before 2026-10-05 predate this key and carry `SHA256SUMS` plus a
build-provenance attestation, but no detached signature.

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
