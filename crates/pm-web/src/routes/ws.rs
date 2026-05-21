//! WebSocket relay routes — M7
//!
//! POST /api/v1/ws/ticket  — create a single-use WS auth ticket (JWT-protected)
//! GET  /api/v1/ws/jobs    — browser WebSocket endpoint (ticket-authenticated)

use axum::{
    extract::ws::{Message, WebSocket},
    extract::{Query, State, WebSocketUpgrade},
    http::StatusCode,
    response::{Json, Response},
    routing::{get, post},
    Router,
};
use chrono::{Duration, Utc};
use pm_auth::rbac::AuthUser;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::postgres::PgListener;
use ulid::Ulid;
use uuid::Uuid;

use crate::AppState;

// ── WsTicket ──────────────────────────────────────────────────────────────────

/// Single-use WebSocket authentication ticket stored in-memory.
#[derive(Debug, Clone)]
pub struct WsTicket {
    pub user_id: Uuid,
    pub role: String,
    pub expires_at: chrono::DateTime<Utc>,
}

// ── Router ────────────────────────────────────────────────────────────────────

/// Router for ticket-issuance endpoint (JWT-protected, merged into protected_api).
pub fn ticket_router() -> Router<AppState> {
    Router::new().route("/ws/ticket", post(create_ticket_handler))
}

/// Router for the WebSocket endpoint (ticket-authenticated, NO JWT middleware).
pub fn ws_router() -> Router<AppState> {
    Router::new().route("/api/v1/ws/jobs", get(ws_handler))
}

// ── Error helper ─────────────────────────────────────────────────────────────

#[inline]
fn err(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({ "error": { "code": code, "message": message.into() } })),
    )
}

// ── POST /api/v1/ws/ticket ────────────────────────────────────────────────────

/// Issue a single-use WebSocket authentication ticket (60 s expiry).
pub async fn create_ticket_handler(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let ticket_id = Ulid::new().to_string();
    let expires_at = Utc::now() + Duration::seconds(60);

    let ticket = WsTicket {
        user_id: auth.user_id,
        role: auth.role.as_str().to_string(),
        expires_at,
    };

    state.ws_tickets.insert(ticket_id.clone(), ticket);

    tracing::info!(
        user_id = %auth.user_id,
        username = %auth.username,
        ticket = %ticket_id,
        "WS ticket issued"
    );

    Ok(Json(json!({ "ticket": ticket_id })))
}

// ── GET /api/v1/ws/jobs ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    pub ticket: String,
}

/// Browser WebSocket upgrade endpoint — authenticates via single-use ticket.
pub async fn ws_handler(
    State(state): State<AppState>,
    Query(q): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response, (StatusCode, Json<Value>)> {
    // Validate and consume the ticket atomically.
    let ticket = {
        let entry = state.ws_tickets.get(&q.ticket);
        match entry {
            None => {
                return Err(err(
                    StatusCode::UNAUTHORIZED,
                    "invalid_ticket",
                    "WebSocket ticket not found or already used",
                ));
            },
            Some(t) => {
                if t.expires_at < Utc::now() {
                    drop(t);
                    state.ws_tickets.remove(&q.ticket);
                    return Err(err(
                        StatusCode::UNAUTHORIZED,
                        "ticket_expired",
                        "WebSocket ticket has expired",
                    ));
                }
                t.clone()
            },
        }
    };
    // Single-use: remove immediately after validation.
    state.ws_tickets.remove(&q.ticket);

    tracing::info!(
        user_id = %ticket.user_id,
        role = %ticket.role,
        "Browser WebSocket connection upgraded"
    );

    let db = state.db.clone();
    Ok(ws.on_upgrade(move |socket| handle_browser_ws(socket, db, ticket)))
}

// ── WebSocket handler ─────────────────────────────────────────────────────────

/// Drive the browser WebSocket: LISTEN on `job_update` and forward payloads.
async fn handle_browser_ws(mut socket: WebSocket, db: sqlx::PgPool, ticket: WsTicket) {
    // Acquire a dedicated PG listener connection.
    let mut listener = match PgListener::connect_with(&db).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(error = %e, user_id = %ticket.user_id, "Failed to create PgListener");
            let _ = socket
                .send(Message::Text(
                    json!({ "error": "internal_error" }).to_string().into(),
                ))
                .await;
            return;
        },
    };

    if let Err(e) = listener.listen("job_update").await {
        tracing::error!(error = %e, user_id = %ticket.user_id, "PgListener LISTEN failed");
        return;
    }

    tracing::info!(user_id = %ticket.user_id, "Browser WS: LISTEN job_update started");

    loop {
        tokio::select! {
            // Forward PG notifications to the browser.
            notify_result = listener.recv() => {
                match notify_result {
                    Ok(notification) => {
                        let payload = notification.payload().to_string();
                        tracing::debug!(user_id = %ticket.user_id, payload = %payload, "Forwarding job_update");
                        if socket.send(Message::Text(payload.into())).await.is_err() {
                            tracing::info!(user_id = %ticket.user_id, "Browser WS send failed — client disconnected");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, user_id = %ticket.user_id, "PgListener recv error");
                        break;
                    }
                }
            }

            // Handle incoming frames from the browser (ping/close).
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => {
                        tracing::info!(user_id = %ticket.user_id, "Browser WS closed by client");
                        break;
                    }
                    Some(Ok(Message::Ping(data))) if socket.send(Message::Pong(data.clone())).await.is_err() => {
                        break;
                    }
                    Some(Err(e)) => {
                        tracing::debug!(error = %e, user_id = %ticket.user_id, "Browser WS recv error");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    tracing::info!(user_id = %ticket.user_id, "Browser WS handler exiting");
}
