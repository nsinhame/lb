//! Shared application state and the CDN-pool abstraction.

use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use heed::{Database, Env};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::config::Config;

// ============================================================
// CDN METADATA (stored as JSON in LMDB)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CdnMeta {
    #[serde(default)]
    pub load: u64,
    /// 1 = online, 0 = offline
    #[serde(default)]
    pub last_ok: u8,
    #[serde(default)]
    pub fail_count: u64,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(rename = "_ts", default)]
    pub ts: u64,
    /// Error description when offline (e.g. "timeout", "HTTP 503")
    #[serde(default)]
    pub error_code: String,
    /// Resolved IP address (used to deduplicate multi-URL CDNs)
    #[serde(default)]
    pub ip: String,
}

// ============================================================
// LMDB type alias
// keys  = &str  (CDN URL)
// values = &[u8] (JSON-encoded CdnMeta)
// ============================================================

pub type CdnDb = Database<heed::types::Str, heed::types::Bytes>;

// ============================================================
// BEST-CDN CACHE
// ============================================================

pub struct BestCdnCache {
    pub url: Option<String>,
    pub updated: Instant,
}

impl Default for BestCdnCache {
    fn default() -> Self {
        // Start with an expired timestamp so the very first request always
        // goes through the full selection logic.
        BestCdnCache {
            url: None,
            updated: Instant::now() - Duration::from_secs(9999),
        }
    }
}

// ============================================================
// SHARED APPLICATION STATE  (cheap to Clone – everything is Arc-backed)
// ============================================================

/// Which downstream project a CDN registry entry / request belongs to. The two
/// pools are fully independent (separate LMDB sub-db, separate Mongo collection,
/// separate best-CDN cache) since the two projects use unrelated hash/token
/// schemes and must never be mixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CdnPool {
    /// plgb (WebStreamer): health-check GET /status, load JSON key "loads".
    Plgb,
    /// telethon-plgb (tgfs): health-check GET / (root), load JSON key "load".
    Telethon,
}

impl CdnPool {
    pub fn lmdb_db(self, state: &AppState) -> CdnDb {
        match self {
            CdnPool::Plgb => state.lmdb_db,
            CdnPool::Telethon => state.lmdb_db_telethon,
        }
    }
    pub fn mongo_col(self, state: &AppState) -> Option<&mongodb::Collection<mongodb::bson::Document>> {
        match self {
            CdnPool::Plgb => state.mongo_cdn_col.as_ref(),
            CdnPool::Telethon => state.mongo_cdn_col_telethon.as_ref(),
        }
    }
    pub fn best_cdn(self, state: &AppState) -> &Arc<RwLock<BestCdnCache>> {
        match self {
            CdnPool::Plgb => &state.best_cdn,
            CdnPool::Telethon => &state.best_cdn_telethon,
        }
    }
    /// Health-check path on the CDN itself (appended directly to the CDN's base URL).
    pub fn health_path(self) -> &'static str {
        match self {
            CdnPool::Plgb => "/status",
            CdnPool::Telethon => "/",
        }
    }
    /// JSON key on the health response holding the per-client load map.
    pub fn load_key(self) -> &'static str {
        match self {
            CdnPool::Plgb => "loads",
            CdnPool::Telethon => "load",
        }
    }
    /// This pool's ad-gating "users" collection (None if not configured).
    pub fn users_col(self, state: &AppState) -> Option<&mongodb::Collection<mongodb::bson::Document>> {
        match self {
            CdnPool::Plgb => state.mongo_users_col.as_ref(),
            CdnPool::Telethon => state.mongo_users_col_telethon.as_ref(),
        }
    }
    /// Field name holding the user id on that pool's users collection.
    pub fn user_id_field(self) -> &'static str {
        match self {
            CdnPool::Plgb => "id",
            CdnPool::Telethon => "_id",
        }
    }
    /// Short tag mixed into signed /ad-tokens so a token issued for one pool
    /// can never be replayed against the other pool's (unrelated) user ids.
    pub fn tag(self) -> &'static str {
        match self {
            CdnPool::Plgb => "plgb",
            CdnPool::Telethon => "telethon",
        }
    }
    /// Route prefix for this pool's /ad-tokens purchase flow.
    pub fn route_prefix(self) -> &'static str {
        match self {
            CdnPool::Plgb => "",
            CdnPool::Telethon => "/t",
        }
    }
    /// Whether ad monetization is globally enabled for this pool
    /// (LB_SHOW_ADS_PLGB / LB_SHOW_ADS_TELETHON).
    pub fn show_ads(self, state: &AppState) -> bool {
        match self {
            CdnPool::Plgb => state.config.show_ads_plgb,
            CdnPool::Telethon => state.config.show_ads_telethon,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub lmdb_env: Arc<Env>,
    /// plgb CDN registry (LMDB sub-db "cdns").
    pub lmdb_db: CdnDb,
    /// telethon-plgb CDN registry (LMDB sub-db "cdns_telethon") — independent pool.
    pub lmdb_db_telethon: CdnDb,
    /// MongoDB "file" collection: keyed by file `_id` (the URL hash). Holds
    /// `special_type` for some files and the owner `user_id` used for ad gating.
    /// (None if MONGO_URL not set)
    pub mongo_col: Option<mongodb::Collection<mongodb::bson::Document>>,
    /// MongoDB collection for plgb CDN registry persistence (None if MONGO_URL not set)
    pub mongo_cdn_col: Option<mongodb::Collection<mongodb::bson::Document>>,
    /// MongoDB collection for telethon-plgb CDN registry persistence (None if MONGO_URL not set)
    pub mongo_cdn_col_telethon: Option<mongodb::Collection<mongodb::bson::Document>>,
    /// MongoDB "users" collection: docs keyed by `id` (= file's `user_id`) and
    /// holding `ad_watch_time`. (None if MONGO_URL not set)
    pub mongo_users_col: Option<mongodb::Collection<mongodb::bson::Document>>,
    /// telethon-plgb's own primary-DB "users" collection: docs keyed by `_id`
    /// (= user_id), holding `join_date`/`plan`/`uf_clusters` plus the
    /// LB-managed `ad_watch_time`. (None if LB_MONGO_TELETHON_URI not set)
    pub mongo_users_col_telethon: Option<mongodb::Collection<mongodb::bson::Document>>,
    /// telethon-plgb's sharded "user_files" collections, one per configured
    /// LB_MONGO_TELETHON_INDEX_URI[N] (index = cluster number, mirroring
    /// telethon-plgb's own `uf_clusters`). Falls back to a single entry backed
    /// by the primary connection when no shard URIs are configured. Empty when
    /// LB_MONGO_TELETHON_URI is not set.
    pub mongo_user_files_cols_telethon: Vec<mongodb::Collection<mongodb::bson::Document>>,
    /// key = file hash, value = special_type ("zero_ad", "one_ad", "two_ad", …)
    pub special_hashes: Arc<DashMap<String, String>>,
    pub best_cdn: Arc<RwLock<BestCdnCache>>,
    pub best_cdn_telethon: Arc<RwLock<BestCdnCache>>,
    /// key = "ip:hash", value = list of request timestamps
    pub rate_limiter: Arc<DashMap<String, Vec<Instant>>>,
    pub trusted_hosts: Arc<RwLock<HashSet<String>>>,
    pub config: Arc<Config>,
    pub http_client: Client,
}
