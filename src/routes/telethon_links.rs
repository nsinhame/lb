//! /t/dl and /t/wt route handlers (telethon-plgb pool): ad-callback token
//! detection, per-user ad gating, then redirect to the best CDN.
//!
//! Route is `*rest` (not a plain `:sig`) so an ad-callback token can be
//! squeezed in as `<token>/<sig>`, mirroring plgb's `*filename` trick.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;
use serde_json::json;

use crate::ads::arolinks::telethon_ad_redirect;
use crate::ads::tokens::{looks_like_ad_token, verify_telethon_ad_token};
use crate::cdn_selection::get_best_cdn;
use crate::http_utils::redirect_to;
use crate::mongo::ad_gating_telethon::{telethon_should_show_ads, telethon_update_ad_watch_time};
use crate::state::{AppState, CdnPool};

#[derive(Deserialize)]
pub struct PayloadRestPath {
    payload: String,
    rest: String,
}

/// Shared request pipeline for both /t/dl and /t/wt.
async fn serve_telethon(state: &AppState, headers: &HeaderMap, path: &str, payload: &str, mut rest: String) -> Response {
    // 0. Ad callback: <token>/<sig> — a valid, unexpired token proves the user
    //    went through the ad flow, so record the watch time and redirect to
    //    the clean link. An invalid/expired token-shaped segment is stripped
    //    so the request re-gates instead of leaking it into the CDN path.
    if let Some(slash) = rest.find('/') {
        let seg = rest[..slash].to_string();
        if looks_like_ad_token(&seg) {
            let sig = rest[slash + 1..].to_string();
            if verify_telethon_ad_token(&state.config.ad_secret, path, payload, &sig, &seg) {
                telethon_update_ad_watch_time(state, payload).await;
                return redirect_to(state, &format!("/t/{}/{}/{}", path, payload, sig));
            }
            rest = sig;
        }
    }
    let sig = rest;

    // 1. Per-user ad gate (independent LB_SHOW_ADS_TELETHON toggle from plgb's).
    if state.config.show_ads_telethon
        && state.config.arolinks_api.is_some()
        && telethon_should_show_ads(state, payload).await
    {
        if let Some(resp) = telethon_ad_redirect(state, headers, path, payload, &sig).await {
            return resp;
        }
        // Ad could not be built (no Host / shorten failed) → serve directly.
    }

    // 2. Redirect to the best telethon-plgb CDN.
    match get_best_cdn(state, CdnPool::Telethon).await {
        Some(cdn) => redirect_to(state, &format!("{}/{}/{}/{}", cdn, path, payload, sig)),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "No CDN online"})),
        )
            .into_response(),
    }
}

pub async fn t_dl(
    State(state): State<AppState>,
    Path(PayloadRestPath { payload, rest }): Path<PayloadRestPath>,
    headers: HeaderMap,
) -> Response {
    serve_telethon(&state, &headers, "dl", &payload, rest).await
}

pub async fn t_wt(
    State(state): State<AppState>,
    Path(PayloadRestPath { payload, rest }): Path<PayloadRestPath>,
    headers: HeaderMap,
) -> Response {
    serve_telethon(&state, &headers, "wt", &payload, rest).await
}
