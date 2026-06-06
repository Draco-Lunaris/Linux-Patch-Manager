# Agent Client Certificates

**⚠️ Private keys are NOT committed to version control.**

This directory holds mTLS certificates used by `pm-agent-client` for testing.
The entire directory is excluded from git via `.gitignore`.

## Generating Test Certificates

Certificates are generated automatically on first run by the `pm-ca` service,
or you can generate them manually for development:

```bash
# Create certs directory if it doesn't exist
mkdir -p crates/pm-agent-client/certs

# Generate using the pm-ca service (preferred)
# Or copy from /etc/patch-manager/certs/ on a deployed host
```

## Production Deployment

Production certificates are managed by `pm-ca` at `/etc/patch-manager/certs/`.
The `pm-agent-client` reads certificates from file paths configured in
`config.toml` (`agent_client_cert_path`, `agent_client_key_path`, `ca_cert_path`).

## Security

- **Never commit private keys** (`*.key`, `*.key.pem`) to version control
- The `gitleaks` CI check scans for accidentally committed secrets
- See `SECURITY.md` and `docs/security-review.md` for full details
