//! Outbound Arolinks shortening calls + the ad-redirect flows for /dl,
//! /watch, and their telethon-plgb (/t/dl, /t/wt) counterparts.

use std::time::Duration;

use axum::http::{header, HeaderMap};
use axum::response::Response;
use reqwest::Client;
use serde_json::Value;

use crate::ads::pages::ad_interstitial_page;
use crate::ads::tokens::{sign_ad_token, sign_telethon_ad_token};
use crate::constants::AD_TOKEN_TTL_SECS;
use crate::link_kind::LinkKind;
use crate::state::AppState;
use crate::time_utils::now_unix;

pub async fn arolinks_shorten(client: &Client, api: &str, endpoint: &str, raw_url: &str) -> Option<String> {
    let resp = client
        .get(endpoint)
        .query(&[("api", api), ("url", raw_url)])
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;
    let js: Value = resp.json().await.ok()?;
    if js.get("status")?.as_str()? == "success" {
        js.get("shortenedUrl")?.as_str().map(|s| s.to_string())
    } else {
        None
    }
}

/// Reconstruct the public base URL (scheme://host) the client originally hit,
/// so the arolinks destination points back at this load balancer.
pub fn public_base_url(headers: &HeaderMap) -> Option<String> {
    let host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get(header::HOST).and_then(|v| v.to_str().ok()))
        .filter(|h| !h.is_empty())?;
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    Some(format!("{}://{}", proto, host))
}

/// Build an arolinks ad whose final destination is the LB callback URL
/// `<base>/<kind>/<hash>/<token>/<filename>`, wrapped in a friendly interstitial
/// page that explains the flow before redirecting. Returns None when an ad
/// cannot be built (arolinks unconfigured, Host missing, or the shorten call
/// failed) so the caller can serve the content directly instead.
pub async fn ad_redirect(
    state: &AppState,
    headers: &HeaderMap,
    kind: LinkKind,
    hash: &str,
    filename: &str,
) -> Option<Response> {
    let api = state.config.arolinks_api.as_ref()?;
    let base = public_base_url(headers)?;
    let exp = now_unix() + AD_TOKEN_TTL_SECS;
    let token = sign_ad_token(&state.config.ad_secret, kind, hash, filename, exp);
    let callback = format!("{}/{}/{}/{}/{}", base, kind.path(), hash, token, filename);
    let short = arolinks_shorten(
        &state.http_client,
        api,
        &state.config.arolinks_endpoint,
        &callback,
    )
    .await?;
    let action = match kind {
        LinkKind::Dl => "your download will start",
        LinkKind::Watch => "your video will start playing",
    };
    Some(ad_interstitial_page(&short, action))
}

/// Telethon-plgb equivalent of `ad_redirect`: callback URL is
/// `<base>/t/<path>/<payload>/<token>/<sig>` (token inserted between payload
/// and sig, symmetric to plgb's hash/token/filename layout).
pub async fn telethon_ad_redirect(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    payload: &str,
    sig: &str,
) -> Option<Response> {
    let api = state.config.arolinks_api.as_ref()?;
    let base = public_base_url(headers)?;
    let exp = now_unix() + AD_TOKEN_TTL_SECS;
    let token = sign_telethon_ad_token(&state.config.ad_secret, path, payload, sig, exp);
    let callback = format!("{}/t/{}/{}/{}/{}", base, path, payload, token, sig);
    let short = arolinks_shorten(
        &state.http_client,
        api,
        &state.config.arolinks_endpoint,
        &callback,
    )
    .await?;
    let action = if path == "dl" {
        "your download will start"
    } else {
        "your video will start playing"
    };
    Some(ad_interstitial_page(&short, action))
}
