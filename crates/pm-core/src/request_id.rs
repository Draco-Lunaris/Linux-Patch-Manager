use axum::{extract::Request, http::HeaderValue, middleware::Next, response::Response};
use ulid::Ulid;

/// HTTP header name for request correlation IDs.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

/// Axum middleware that generates a ULID request ID and attaches it
/// to both the request extensions and the response header.
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    // Use existing X-Request-Id if provided by upstream proxy, else generate
    let id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| Ulid::new().to_string());

    // Insert as extension so handlers can access it
    req.extensions_mut().insert(RequestId(id.clone()));

    let mut response = next.run(req).await;

    // Echo the ID back in the response
    if let Ok(value) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }

    response
}

/// Extractor type for retrieving the request ID inside handlers.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
