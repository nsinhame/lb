//! Best-CDN selection: lowest load (±1 tie-break), deduplicated by IP, cached.

use std::collections::HashMap;
use std::time::Instant;

use rand::seq::SliceRandom;

use crate::lmdb_store::lmdb_list_cdns;
use crate::state::{AppState, CdnPool};

pub async fn get_best_cdn(state: &AppState, pool: CdnPool) -> Option<String> {
    // Return cached value if still fresh
    {
        let cache = pool.best_cdn(state).read().await;
        if let Some(ref url) = cache.url {
            if cache.updated.elapsed() < state.config.best_cdn_ttl {
                return Some(url.clone());
            }
        }
    }

    let cdns = lmdb_list_cdns(state, pool).await;

    // Deduplicate by IP: if two URLs resolve to the same server, only count once.
    // For each IP group, keep the URL with the lowest load.
    let mut ip_best: HashMap<String, (String, u64)> = HashMap::new();
    for (url, meta) in &cdns {
        if meta.last_ok != 1 {
            continue;
        }
        // Fall back to URL as key when IP is unknown (avoids false dedup)
        let key = if meta.ip.is_empty() { url.clone() } else { meta.ip.clone() };
        match ip_best.get(&key) {
            None => {
                ip_best.insert(key, (url.clone(), meta.load));
            }
            Some((_, prev_load)) if meta.load < *prev_load => {
                ip_best.insert(key, (url.clone(), meta.load));
            }
            _ => {}
        }
    }

    // Lowest load among deduplicated online CDNs
    let min_load = ip_best.values().map(|(_, l)| *l).min()?;

    // All CDNs within ±1 load unit of the minimum
    let candidates: Vec<String> = ip_best
        .into_values()
        .filter(|(_, l)| l.abs_diff(min_load) <= 1)
        .map(|(u, _)| u)
        .collect();

    let chosen = candidates.choose(&mut rand::thread_rng()).cloned()?;

    // Cache the result
    {
        let mut cache = pool.best_cdn(state).write().await;
        cache.url = Some(chosen.clone());
        cache.updated = Instant::now();
    }

    Some(chosen)
}
