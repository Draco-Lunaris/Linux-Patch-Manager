# Reverse Proxy Deployment Runbook

**Audience:** Operators deploying `pm-web` behind a reverse proxy (nginx,
HAProxy, Cloudflare, AWS ALB, etc.).

**Related:**
- `docs/security-review.md` §1.3 (IP Whitelist Enforcement)
- `tasks/ip-allowlist-spec.md` §7 (Risk Analysis)
- Issue [#3](https://github.com/Draco-Lunaris/Linux-Patch-Manager/issues/3)

---

## TL;DR

If you front `pm-web` with a reverse proxy, you **MUST** add the proxy's
IP address (or CIDR) to `security.trusted_proxies` in
`/etc/patch-manager/config.toml`. If you do not, the IP allowlist will
evaluate against the proxy's IP (not the real client) and will return
`403 forbidden_ip` for legitimate traffic.

## Why

Starting with the IP-allowlist hardening in issue #3, `pm-web` no longer
trusts `X-Forwarded-For` by default. The default behavior is **strict**:

1. The server reads the socket peer IP from `ConnectInfo<SocketAddr>`.
2. The server checks that IP against `security.ip_whitelist`.
3. `X-Forwarded-For` is **ignored** unless the socket peer is in
   `security.trusted_proxies`.

When you put a reverse proxy in front, every connection's socket peer IP
is the proxy's address. Without `trusted_proxies` set, the proxy's IP is
checked against your allowlist — and unless your allowlist happens to
include the proxy (which would defeat the purpose of the allowlist),
the request is denied.

## How to Fix

1. Identify the **egress IP** of your reverse proxy (the IP `pm-web`
   sees as the immediate TCP peer). This is typically:
   - nginx: the IP nginx binds to internally, or the host's IP if nginx
     runs on the same host as `pm-web` (port forward).
   - Cloudflare: see
     [Cloudflare IP ranges](https://www.cloudflare.com/ips/).
   - AWS ALB / NLB: the ALB/NLB's private IP from the VPC.
   - HAProxy: the bind address.

2. Add the IP (or CIDR for multiple hops) to `trusted_proxies` in
   `/etc/patch-manager/config.toml`:

   ```toml
   [security]
   ip_whitelist = ["10.0.0.0/8"]            # example: corporate clients
   trusted_proxies = ["172.16.5.10/32"]     # example: reverse proxy egress
   ```

3. **Restart `pm-web`** for the config to take effect. The
   `trusted_proxies` field is read at startup; runtime updates are
   supported via `AuthConfig::update_trusted_proxies` but not yet
   exposed through a settings endpoint.

4. Verify by tailing the logs and confirming that requests with
   `X-Forwarded-For: <allowed-client-ip>` succeed (status 200/401, NOT
   403) when the request comes through the proxy.

## Multi-hop Proxy Chains

If you have multiple proxies in front of `pm-web` (e.g., Cloudflare →
nginx → pm-web), add **each hop you control** to `trusted_proxies`:

```toml
trusted_proxies = [
    "172.16.5.10/32",   # nginx egress (immediate peer)
    "10.0.0.0/8",       # internal network (in case nginx runs on a different host)
]
```

The resolver picks the leftmost entry of `X-Forwarded-For` when the
immediate peer is in `trusted_proxies`. With two trusted hops, the
resolver will pick the leftmost untrusted IP (the real client).

## Reverse Proxy Headers (recommended)

In addition to the `trusted_proxies` config, configure your reverse
proxy to:

- **Append** to `X-Forwarded-For` (not replace) so the chain is
  preserved through multiple hops.
- Set `X-Real-IP` (optional, informational; pm-web currently uses
  `X-Forwarded-For`).
- Forward the original `Host` header so SAML/OIDC redirects work
  correctly.
- Do **not** strip the `Authorization` header.

### nginx example

```nginx
location /api/ {
    proxy_pass http://127.0.0.1:12443;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

The `proxy_add_x_forwarded_for` directive appends, which is what you want.

## Troubleshooting

### All requests return 403 forbidden_ip

- Check that `trusted_proxies` is set and contains the proxy's IP.
- Check that the proxy's IP is correct (run `ss -tnp` on the pm-web
  host to see the actual peer address).
- Check `tracing` logs for `reason = "unresolvable_client_ip"` — this
  means the `ConnectInfo<SocketAddr>` extension is missing (the
  listener wasn't built with `into_make_service_with_connect_info`).

### XFF is being ignored

- Check that the immediate peer's IP is in `trusted_proxies`. If the
  immediate peer is NOT in `trusted_proxies`, XFF is ignored (correct
  behavior).
- Check the XFF format: pm-web parses the leftmost entry, trimmed of
  whitespace. A malformed leftmost entry falls back to the socket peer.

### Multiple IPs in XFF and only the last hop is trusted

- If you have one trusted proxy and one untrusted, the resolver will
  only use XFF when the immediate peer (the trusted one) is in the
  list. The XFF is parsed leftmost-first, so the real client IP (leftmost
  untrusted hop) is used.
- If neither hop is in `trusted_proxies`, XFF is ignored and the
  socket peer IP (the immediate proxy) is used. Add the immediate
  proxy to `trusted_proxies` to fix.

## See Also

- `config/config.example.toml` — inline documentation on `trusted_proxies`.
- `tasks/ip-allowlist-spec.md` §3 (Design Decisions) for the rationale.
- `crates/pm-auth/src/rbac.rs` — the resolver implementation.
