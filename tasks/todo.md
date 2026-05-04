# WebSocket + Polling Fallback Implementation Plan

## Problem
The linux-patch-api agent's `/api/v1/ws/jobs` endpoint was a stub that returned HTTP 101
with a JSON body but didn't compute the required `Sec-WebSocket-Accept` header. This
caused the pm-worker WS relay to fail with "Key mismatch in Sec-WebSocket-Accept header".

Additionally, the pm-worker WS relay's rustls ClientConfig didn't set ALPN to http/1.1,
causing HTTP/2 negotiation which also breaks WebSocket upgrades.

## Root Causes
1. **Agent WS handler was a stub** — didn't implement RFC 6455 WebSocket handshake
2. **WS relay missing ALPN** — rustls ClientConfig didn't set `alpn_protocols` to `http/1.1`
3. **No fallback** — WS relay had no fallback if WebSocket connection failed

## Completed
- [x] ALPN fix in pm-worker ws_relay.rs (forces HTTP/1.1 for WebSocket)
- [x] Error chain logging in pm-worker ws_relay.rs (for future debugging)
- [x] Job-level WS event_type fix (frontend + backend)
- [x] Implement proper WebSocket in linux-patch-api using actix-web-actors
- [x] Add WsJobActor with broadcast channel for real-time status updates
- [x] Add HTTP polling fallback in pm-worker WS relay
- [x] Deploy both binaries to dev LXC
- [x] Push both projects to Gitea
- [x] Fix config file (ws_relay_poll_interval_secs in [worker] section)

## Deployment Notes
- linux-patch-api binary deployed to /usr/bin/linux-patch-api on dev LXC (VMID 131)
- pm-worker binary deployed to /usr/local/bin/pm-worker on dev LXC (VMID 131)
- Config file: /etc/patch-manager/config.toml (added ws_relay_poll_interval_secs = 10)
- Both services running: patch-manager-web, patch-manager-worker, linux-patch-api

## Verified Working
- WebSocket connections to linux-patch-manager-dev (agent with proper WS handler)
- HTTP polling fallback to gitea-runner-u2404 (agent with stub WS)
- Job completion status updates via pg_notify
- Frontend real-time updates via WebSocket events
