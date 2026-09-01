//! Admin `/stats` JSON endpoint (feeds the /nitai dashboard).

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Json, Response};
use serde_json::{json, Value};

use crate::admin_auth::check_admin;
use crate::cdn_selection::get_best_cdn;
use crate::lmdb_store::lmdb_list_cdns;
use crate::state::{AppState, CdnMeta, CdnPool};

fn cdn_list_json(cdns: &[(String, CdnMeta)], fail_threshold: u64) -> Vec<Value> {
    cdns.iter()
        .map(|(url, meta)| {
            json!({
                "url": url,
                "load": meta.load,
                "last_ok": meta.last_ok,
                "fail_count": format!("{}/{}", meta.fail_count, fail_threshold),
                "updated_at": meta.updated_at,
                "error_code": meta.error_code,
                "ip": meta.ip,
            })
        })
        .collect()
}

pub async fn stats(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(e) = check_admin(&headers, &state.config) {
        return e;
    }
    let cdns = lmdb_list_cdns(&state, CdnPool::Plgb).await;
    let cdn_list = cdn_list_json(&cdns, state.config.fail_threshold);

    let cdns_telethon = lmdb_list_cdns(&state, CdnPool::Telethon).await;
    let cdn_list_telethon = cdn_list_json(&cdns_telethon, state.config.fail_threshold);

    let trusted: Vec<String> = {
        let mut v: Vec<_> = state.trusted_hosts.read().await.iter().cloned().collect();
        v.sort();
        v
    };
    let best = get_best_cdn(&state, CdnPool::Plgb).await;
    let best_telethon = get_best_cdn(&state, CdnPool::Telethon).await;

    Json(json!({
        "cdns": cdn_list,
        "trusted_hosts": trusted,
        "best_cdn": best,
        "cdns_telethon": cdn_list_telethon,
        "best_cdn_telethon": best_telethon,
    }))
    .into_response()
}
