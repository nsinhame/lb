//! Trusted-host whitelist (CDN hostnames + loopback) and referer blocking.
//! Both are plgb-only concepts (telethon-plgb has no referer-blocking equivalent).

use axum::http::HeaderMap;

use crate::lmdb_store::lmdb_list_cdns;
use crate::state::{AppState, CdnPool};

// ============================================================
// TRUSTED HOSTS  (CDN hostnames + loopback)
// ============================================================

pub async fn rebuild_trusted_hosts(state: &AppState) {
    let cdns = lmdb_list_cdns(state, CdnPool::Plgb).await;
    let mut hosts = state.trusted_hosts.write().await;
    hosts.clear();
    hosts.insert("localhost".to_string());
    hosts.insert("127.0.0.1".to_string());
    hosts.insert("::1".to_string());
    for (url, _) in &cdns {
        if let Ok(parsed) = url.parse::<url::Url>() {
            if let Some(host) = parsed.host_str() {
                hosts.insert(host.to_lowercase());
            }
        }
    }
}

// ============================================================
// REFERER BLOCKING
// ============================================================

pub async fn referer_blocked(state: &AppState, headers: &HeaderMap, ip: &str) -> bool {
    if ip == "127.0.0.1" || ip == "::1" {
        return false;
    }

    let Some(referer) = headers.get("referer").and_then(|v| v.to_str().ok()) else {
        return false; // no referer → allow (same behaviour as Python)
    };

    let Some(host) = referer
        .parse::<url::Url>()
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
    else {
        return false;
    };

    // CDN hostnames and loopback are always trusted
    {
        let trusted = state.trusted_hosts.read().await;
        if trusted.contains(&host) {
            return false;
        }
    }

    // Block if not in the explicit whitelist
    !state
        .config
        .referer_whitelist
        .iter()
        .any(|w| host == *w || host.ends_with(&format!(".{}", w)))
}
