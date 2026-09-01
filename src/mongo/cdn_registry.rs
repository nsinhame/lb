//! CDN registry persistence in MongoDB (`cdn_registry` / `cdn_registry_telethon`).

use mongodb::bson::doc;

use crate::lmdb_store::{lmdb_get_cdn, lmdb_set_cdn};
use crate::state::{AppState, CdnMeta, CdnPool};

/// Upsert a CDN URL into the pool's MongoDB cdn_registry collection.
pub async fn mongo_add_cdn(state: &AppState, pool: CdnPool, url: &str) {
    let Some(col) = pool.mongo_col(state) else { return };
    let filter = doc! { "_id": url };
    let update = doc! { "$setOnInsert": { "_id": url } };
    let opts = mongodb::options::UpdateOptions::builder().upsert(true).build();
    if let Err(e) = col.update_one(filter, update, opts).await {
        tracing::warn!("MongoDB cdn_registry upsert error for {}: {}", url, e);
    }
}

/// Remove a CDN URL from the pool's MongoDB cdn_registry collection.
pub async fn mongo_remove_cdn(state: &AppState, pool: CdnPool, url: &str) {
    let Some(col) = pool.mongo_col(state) else { return };
    if let Err(e) = col.delete_one(doc! { "_id": url }, None).await {
        tracing::warn!("MongoDB cdn_registry delete error for {}: {}", url, e);
    }
}

/// Load CDN URLs persisted in MongoDB (pool's cdn_registry collection) into this
/// instance's LMDB pool, defaulting each to an "offline, unknown" state until the
/// poller confirms it (or the immediate-probe path in add_cdn_generic does).
pub async fn load_persisted_cdns(state: &AppState, pool: CdnPool) -> usize {
    let Some(cdn_col) = pool.mongo_col(state) else { return 0 };
    let mut loaded = 0usize;
    match cdn_col.find(None, None).await {
        Ok(mut cursor) => loop {
            match cursor.advance().await {
                Ok(true) => {
                    if let Ok(doc) = cursor.deserialize_current() {
                        if let Ok(url) = doc.get_str("_id").map(|s| s.to_string()) {
                            if url.starts_with("http") && lmdb_get_cdn(state, pool, url.clone()).await.is_none() {
                                lmdb_set_cdn(
                                    state,
                                    pool,
                                    url,
                                    CdnMeta {
                                        load: 99999,
                                        last_ok: 0,
                                        fail_count: 0,
                                        ..Default::default()
                                    },
                                )
                                .await;
                                loaded += 1;
                            }
                        }
                    }
                }
                _ => break,
            }
        },
        Err(e) => tracing::error!("MongoDB error loading cdn_registry: {}", e),
    }
    loaded
}

/// Seed CDN URLs from a comma-separated env var (e.g. LB_CDN_URLS[_TELETHON]).
pub async fn seed_cdns_from_env(state: &AppState, pool: CdnPool, var_name: &str) {
    let Ok(env_cdns) = std::env::var(var_name) else { return };
    for raw in env_cdns.split(',') {
        let u = raw.trim().trim_end_matches('/').to_string();
        if u.starts_with("http") && lmdb_get_cdn(state, pool, u.clone()).await.is_none() {
            lmdb_set_cdn(
                state,
                pool,
                u.clone(),
                CdnMeta {
                    load: 99999,
                    last_ok: 0,
                    fail_count: 0,
                    ..Default::default()
                },
            )
            .await;
            mongo_add_cdn(state, pool, &u).await;
        }
    }
}
