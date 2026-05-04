# WebSocket + Polling Fallback Implementation Plan

## Problem
The linux-patch-api agent's `/api/v1/ws/jobs` endpoint is a stub that returns HTTP 101
with a JSON body but doesn't compute the required `Sec-WebSocket-Accept` header. This
causes the pm-worker WS relay to fail with "Key mismatch in Sec-WebSocket-Accept header".

Additionally, the pm-worker WS relay's rustls ClientConfig didn't set ALPN to http/1.1,
causing HTTP/2 negotiation which also breaks WebSocket upgrades.

## Root Causes
1. **Agent WS handler is a stub** — doesn't implement RFC 6455 WebSocket handshake
2. **WS relay missing ALPN** — rustls ClientConfig didn't set `alpn_protocols` to `http/1.1`
3. **No fallback** — WS relay has no fallback if WebSocket fails

## Completed
- [x] ALPN fix in pm-worker ws_relay.rs (forces HTTP/1.1 for WebSocket)
- [x] Error chain logging in pm-worker ws_relay.rs (for future debugging)
- [x] Job-level WS event_type fix (frontend + backend)

## Remaining Tasks

### Phase 1: Implement proper WebSocket in linux-patch-api
- [ ] Replace stub `websocket_handler` in `src/api/handlers/websocket.rs` with proper actix-web-actors WebSocket
- [ ] Create `WsJobActor` that:
  - Accepts WebSocket connections via `actix_web_actors::ws::start()`
  - Subscribes to job status updates from `JobManager`
  - Streams job status events to connected clients
  - Handles subscribe/unsubscribe messages
- [ ] Wire up broadcast channel from JobManager to WebSocket actors
- [ ] Build and deploy to dev LXC

### Phase 2: Add polling fallback in pm-worker WS relay
- [ ] In `relay_one_job()`, if WebSocket connection fails, fall back to HTTP polling
- [ ] Use existing `AgentClient` (reqwest + mTLS) to poll `/api/v1/jobs/{id}`
- [ ] Poll interval: configurable, default 5-10 seconds
- [ ] Convert polled job status to same event format as WebSocket messages
- [ ] Fire `pg_notify('job_update')` for polled status changes

### Phase 3: Testing & Deployment
- [ ] Test WebSocket connection on dev LXC
- [ ] Test polling fallback on dev LXC
- [ ] Verify job completion status updates in UI
- [ ] Push to Gitea
- [ ] Update dev LXC deployment

## Architecture Notes

### linux-patch-api WebSocket (Phase 1)
- Uses `actix-web-actors::ws` for proper RFC 6455 WebSocket handshake
- `WsJobActor` implements `actix::Actor` + `StreamHandler<ws::Message>`
- JobManager has a `tokio::sync::broadcast` channel for status updates
- WsJobActor subscribes to this channel and forwards events to clients

### pm-worker WS relay fallback (Phase 2)
- `relay_one_job()` tries WebSocket first
- On connection failure, falls back to `poll_job_status()` using AgentClient
- Poll interval configurable via `[worker]` config (default: 10s)
- Status changes trigger `pg_notify('job_update')` same as WebSocket events
