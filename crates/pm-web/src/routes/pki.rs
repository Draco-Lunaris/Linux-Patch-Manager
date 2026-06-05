//! PKI endpoints for certificate revocation list (CRL) distribution.
//!
//! This module exposes the CRL endpoint that agents poll every 24 hours to
//! check for revoked certificates. The CRL is signed by the internal CA and
//! is publicly accessible (CRLs are self-authenticating — they carry the CA
//! signature and do not require client authentication).

use crate::AppState;
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};

/// Define public PKI routes.
///
/// These endpoints are **unauthenticated** because CRLs are self-authenticating:
/// the agent verifies the CRL signature against its pinned CA certificate.
/// No client certificate or API key is required.
pub fn router() -> Router<AppState> {
    Router::new().route("/pki/crl.pem", get(get_crl))
}

/// `GET /api/v1/pki/crl.pem`
///
/// Returns the current Certificate Revocation List (CRL) as a PEM-encoded
/// X.509 CRL. The CRL is signed by the internal CA and contains the serial
/// numbers of all revoked certificates that have not yet expired.
///
/// # Cache headers
///
/// The response includes `Cache-Control: max-age=3600` (1 hour) to allow
/// intermediate caches to serve the CRL. Agents refresh every 24 hours,
/// so a 1-hour cache is a reasonable balance between freshness and load.
///
/// # CRL generation
///
/// The CRL is generated on demand from the `certificates` table. For our
/// target scale (max ~2500 clients), this is a fast query and the resulting
/// CRL is KB-range. If performance becomes a concern, the CRL can be cached
/// in memory and regenerated on a schedule (see background task in main.rs).
async fn get_crl(State(state): State<AppState>) -> impl IntoResponse {
    match state.ca.generate_crl(&state.db).await {
        Ok(crl_pem) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                "application/x-pem-file; charset=utf-8",
            )],
            [(header::CACHE_CONTROL, "max-age=3600")],
            crl_pem,
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to generate CRL");
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate CRL").into_response()
        },
    }
}
