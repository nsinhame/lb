//! Admin endpoints for registering CDNs and reloading special hashes.

use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};

use crate::admin_auth::check_admin;
use crate::health_check::check_cdn_health;
use crate::lmdb_store::{lmdb_get_cdn, lmdb_set_cdn};
use crate::mongo::cdn_registry::mongo_add_cdn;
use crate::mongo::special_hashes::load_special_hashes;
use crate::state::{AppState, CdnMeta, CdnPool};
use crate::time_utils::now_unix;
use crate::trusted_hosts::rebuild_trusted_hosts;

async fn add_cdn_generic(state: AppState, headers: HeaderMap, body: Value, pool: CdnPool) -> Response {
    if let Err(e) = check_admin(&headers, &state.config) {
        return e;
    }
    let mut added = Vec::new();
    if let Some(urls) = body.get("urls").and_then(|u| u.as_array()) {
        for u in urls {
            if let Some(url_str) = u.as_str() {
                let url = url_str.trim_end_matches('/').to_string();
                if url.starts_with("http")
                    && lmdb_get_cdn(&state, pool, url.clone()).await.is_none()
                {
                    lmdb_set_cdn(
                        &state,
                        pool,
                        url.clone(),
                        CdnMeta {
                            load: 99999,
                            last_ok: 0,
                            fail_count: 0,
                            ..Default::default()
                        },
                    )
                    .await;
                    mongo_add_cdn(&state, pool, &url).await;
                    added.push(url);
                }
            }
        }
    }
    // Trusted-host whitelisting backs referer-blocking, a plgb-only concept.
    if pool == CdnPool::Plgb {
        rebuild_trusted_hosts(&state).await;
    }

    // Immediately poll newly added CDNs so they become available within seconds
    if !added.is_empty() {
        let s = state.clone();
        let urls_to_probe = added.clone();
        tokio::spawn(async move {
            let mut handles = Vec::with_capacity(urls_to_probe.len());
            for url in &urls_to_probe {
                let client = s.http_client.clone();
                let url = url.clone();
                handles.push(tokio::spawn(check_cdn_health(client, url, pool)));
            }
            for handle in handles {
                let Ok((url, ok, load, error_code, ip)) = handle.await else {
                    continue;
                };
                if ok {
                    lmdb_set_cdn(
                        &s,
                        pool,
                        url.clone(),
                        CdnMeta {
                            load,
                            last_ok: 1,
                            fail_count: 0,
                            updated_at: now_unix(),
                            error_code: String::new(),
                            ip,
                            ts: 0,
                        },
                    )
                    .await;
                    tracing::info!("CDN {} is online (load={})", url, load);
                } else {
                    tracing::warn!("CDN {} did not respond to initial health check: {}", url, error_code);
                }
            }
            // Invalidate cache so next request picks up the new CDN immediately
            let mut cache = pool.best_cdn(&s).write().await;
            cache.url = None;
            cache.updated = Instant::now() - Duration::from_secs(9999);
        });
    }

    Json(json!({"added": added})).into_response()
}

pub async fn add_cdn(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Json(body): axum::extract::Json<Value>,
) -> Response {
    add_cdn_generic(state, headers, body, CdnPool::Plgb).await
}

pub async fn add_cdn_telethon(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Json(body): axum::extract::Json<Value>,
) -> Response {
    add_cdn_generic(state, headers, body, CdnPool::Telethon).await
}

/// Admin-only: re-sync special_hashes from MongoDB, triggered by external backend.
pub async fn reload_special(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(e) = check_admin(&headers, &state.config) {
        return e;
    }
    load_special_hashes(&state).await;
    Json(json!({
        "reloaded": true,
        "count": state.special_hashes.len()
    }))
    .into_response()
}
