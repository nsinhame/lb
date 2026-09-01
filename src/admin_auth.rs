//! Admin-key authentication for privileged endpoints.

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde_json::json;

use crate::config::Config;

pub fn check_admin(headers: &HeaderMap, config: &Config) -> Result<(), Response> {
    let key = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if key != config.admin_key {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"detail": "unauthorized"})),
        )
            .into_response());
    }
    Ok(())
}
