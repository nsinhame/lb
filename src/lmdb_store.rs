//! LMDB-backed CDN registry (all I/O wrapped in spawn_blocking).

use crate::state::{AppState, CdnMeta, CdnPool};
use crate::time_utils::now_unix;

pub async fn lmdb_set_cdn(state: &AppState, pool: CdnPool, url: String, mut meta: CdnMeta) {
    meta.ts = now_unix();
    let env = state.lmdb_env.clone();
    let db = pool.lmdb_db(state);
    let Ok(bytes) = serde_json::to_vec(&meta) else {
        return;
    };
    let _ = tokio::task::spawn_blocking(move || -> heed::Result<()> {
        let mut wtxn = env.write_txn()?;
        db.put(&mut wtxn, url.as_str(), &bytes)?;
        wtxn.commit()
    })
    .await;
}

pub async fn lmdb_delete_cdn(state: &AppState, pool: CdnPool, url: String) {
    let env = state.lmdb_env.clone();
    let db = pool.lmdb_db(state);
    let _ = tokio::task::spawn_blocking(move || -> heed::Result<()> {
        let mut wtxn = env.write_txn()?;
        db.delete(&mut wtxn, url.as_str())?;
        wtxn.commit()
    })
    .await;
}

pub async fn lmdb_get_cdn(state: &AppState, pool: CdnPool, url: String) -> Option<CdnMeta> {
    let env = state.lmdb_env.clone();
    let db = pool.lmdb_db(state);
    tokio::task::spawn_blocking(move || -> Option<CdnMeta> {
        let rtxn = env.read_txn().ok()?;
        // .to_vec() copies the bytes out before the transaction is dropped
        let bytes = db.get(&rtxn, url.as_str()).ok()??.to_vec();
        drop(rtxn);
        serde_json::from_slice(&bytes).ok()
    })
    .await
    .ok()
    .flatten()
}

pub async fn lmdb_list_cdns(state: &AppState, pool: CdnPool) -> Vec<(String, CdnMeta)> {
    let env = state.lmdb_env.clone();
    let db = pool.lmdb_db(state);
    tokio::task::spawn_blocking(move || -> heed::Result<Vec<(String, CdnMeta)>> {
        let rtxn = env.read_txn()?;
        let mut result = Vec::new();
        for item in db.iter(&rtxn)? {
            let (k, v) = item?;
            if let Ok(meta) = serde_json::from_slice::<CdnMeta>(v) {
                result.push((k.to_string(), meta));
            }
        }
        Ok(result)
    })
    .await
    .ok()
    .and_then(|r| r.ok())
    .unwrap_or_default()
}
