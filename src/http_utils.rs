//! Small HTTP response helpers shared across route handlers.

use axum::body::Body;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde_json::json;

use crate::state::AppState;

/// Build a redirect Response to a (relative or absolute) location.
pub fn redirect_to(state: &AppState, location: &str) -> Response {
    match axum::http::Response::builder()
        .status(state.config.redirect_code)
        .header(header::LOCATION, location)
        .body(Body::empty())
    {
        Ok(r) => r.into_response(),
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "invalid redirect URL"})),
        )
            .into_response(),
    }
}
