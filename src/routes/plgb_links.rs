//! /dl and /watch route handlers (plgb pool): ad-callback detection, special
//! hash / referer / per-user ad gating, rate limiting, then serve/redirect.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;
use serde_json::json;

use crate::ads::arolinks::ad_redirect;
use crate::ads::special_redirect::handle_special_redirect;
use crate::ads::tokens::{looks_like_ad_token, verify_ad_token};
use crate::cdn_selection::get_best_cdn;
use crate::http_utils::redirect_to;
use crate::link_kind::LinkKind;
use crate::mongo::ad_gating::{should_show_ads, update_ad_watch_time};
use crate::proxy::stream_upstream;
use crate::rate_limiter::record_ip;
use crate::state::{AppState, CdnPool};
use crate::trusted_hosts::referer_blocked;

#[derive(Deserialize)]
pub struct HashFilePath {
    hash: String,
    filename: String,
}

/// Redirect the client to the best CDN's /dl endpoint.
async fn serve_dl(state: &AppState, hash: &str, filename: &str) -> Response {
    match get_best_cdn(state, CdnPool::Plgb).await {
        Some(cdn) => redirect_to(state, &format!("{}/dl/{}/{}", cdn, hash, filename)),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "No CDN online"})),
        )
            .into_response(),
    }
}

/// Stream the best CDN's /watch endpoint back to the client (rewriting HTML).
async fn serve_watch(state: &AppState, hash: &str, filename: &str, headers: HeaderMap) -> Response {
    match get_best_cdn(state, CdnPool::Plgb).await {
        Some(cdn) => {
            let upstream_url = format!("{}/watch/{}/{}", cdn, hash, filename);
            match stream_upstream(&state.http_client, &upstream_url, headers, hash, filename).await {
                Ok(resp) => resp,
                Err(status) => (status, Json(json!({"error": "upstream error"}))).into_response(),
            }
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "No CDN online"})),
        )
            .into_response(),
    }
}

/// Shared request pipeline for both /dl and /watch.
async fn handle_link(
    state: AppState,
    addr: SocketAddr,
    kind: LinkKind,
    hash: String,
    mut filename: String,
    headers: HeaderMap,
) -> Response {
    let ip = addr.ip().to_string();

    // 0. Ad callback: the arolinks destination is /<kind>/<hash>/<token>/<filename>,
    //    where <token> is an HMAC signature only this server can produce. A valid,
    //    unexpired token proves the user really went through the ad flow, so we
    //    record the watch time and redirect to the real link (which then serves
    //    directly, since the freshly-set ad_watch_time is < 2 days old). A
    //    token-shaped but invalid/expired segment is stripped so the request
    //    re-gates (shows a fresh ad) instead of leaking it into the CDN path.
    if let Some(slash) = filename.find('/') {
        let seg = filename[..slash].to_string();
        if looks_like_ad_token(&seg) {
            let rest = filename[slash + 1..].to_string();
            if verify_ad_token(&state.config.ad_secret, kind, &hash, &rest, &seg) {
                update_ad_watch_time(&state, &hash).await;
                return redirect_to(&state, &format!("/{}/{}/{}", kind.path(), hash, rest));
            }
            filename = rest;
        }
    }

    // 1. Special hash → forced ad flow (unchanged).
    if let Some(stype) = state.special_hashes.get(&hash).map(|v| v.clone()) {
        return handle_special_redirect(&state, &stype).await;
    }

    // 2. Referer blocking (unchanged).
    if referer_blocked(&state, &headers, &ip).await {
        return handle_special_redirect(&state, "one_ad").await;
    }

    // 3. Per-user ad gate. Skipped when ads are disabled for plgb
    //    (LB_SHOW_ADS_PLGB) or arolinks is not configured.
    if state.config.show_ads_plgb
        && state.config.arolinks_api.is_some()
        && should_show_ads(&state, &hash).await
    {
        if let Some(resp) = ad_redirect(&state, &headers, kind, &hash, &filename).await {
            return resp;
        }
        // Ad could not be built (no Host / shorten failed) → serve directly.
    }

    // 4. Rate limit (unchanged).
    if record_ip(&state, &ip, &hash) > state.config.max_requests_per_ip {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "IP limit exceeded"})),
        )
            .into_response();
    }

    // 5. Serve the content.
    match kind {
        LinkKind::Dl => serve_dl(&state, &hash, &filename).await,
        LinkKind::Watch => serve_watch(&state, &hash, &filename, headers).await,
    }
}

pub async fn dl(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(HashFilePath { hash, filename }): Path<HashFilePath>,
    headers: HeaderMap,
) -> Response {
    handle_link(state, addr, LinkKind::Dl, hash, filename, headers).await
}

pub async fn watch(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(HashFilePath { hash, filename }): Path<HashFilePath>,
    headers: HeaderMap,
) -> Response {
    handle_link(state, addr, LinkKind::Watch, hash, filename, headers).await
}
