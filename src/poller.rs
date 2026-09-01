//! Background CDN poller: one instance runs per pool (when IS_LEADER).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::debug;

use crate::health_check::check_cdn_health;
use crate::lmdb_store::{lmdb_delete_cdn, lmdb_list_cdns, lmdb_set_cdn};
use crate::mongo::cdn_registry::mongo_remove_cdn;
use crate::state::{AppState, CdnMeta, CdnPool};
use crate::time_utils::now_unix;
use crate::trusted_hosts::rebuild_trusted_hosts;

pub async fn poller_task(state: AppState, pool: CdnPool) {
    let interval = Duration::from_secs(state.config.poll_interval);
    loop {
        let cdns = lmdb_list_cdns(&state, pool).await;

        // Fan-out: check all CDNs concurrently
        let mut handles = Vec::with_capacity(cdns.len());
        for (url, _) in &cdns {
            let client = state.http_client.clone();
            let url = url.clone();
            handles.push(tokio::spawn(check_cdn_health(client, url, pool)));
        }

        // Build a lookup map for previous fail counts
        let prev_map: HashMap<String, CdnMeta> = cdns.into_iter().collect();

        for handle in handles {
            let Ok((url, ok, load, error_code, ip)) = handle.await else {
                continue;
            };
            let prev_fail = prev_map.get(&url).map(|m| m.fail_count).unwrap_or(0);

            if ok {
                lmdb_set_cdn(
                    &state,
                    pool,
                    url,
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
            } else {
                let fail_count = prev_fail + 1;
                if fail_count >= state.config.fail_threshold {
                    debug!("Purging dead CDN: {}", url);
                    mongo_remove_cdn(&state, pool, &url).await;
                    lmdb_delete_cdn(&state, pool, url).await;
                } else {
                    lmdb_set_cdn(
                        &state,
                        pool,
                        url,
                        CdnMeta {
                            load: 99999,
                            last_ok: 0,
                            fail_count,
                            updated_at: now_unix(),
                            error_code,
                            ip,
                            ts: 0,
                        },
                    )
                    .await;
                }
            }
        }

        // Trusted-host whitelisting backs referer-blocking, a plgb-only concept.
        if pool == CdnPool::Plgb {
            rebuild_trusted_hosts(&state).await;
        }

        // Invalidate best-CDN cache so next request re-evaluates with fresh loads
        {
            let mut cache = pool.best_cdn(&state).write().await;
            cache.url = None;
            cache.updated = Instant::now() - Duration::from_secs(9999);
        }

        tokio::time::sleep(interval).await;
    }
}
