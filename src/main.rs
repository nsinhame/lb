//! Async HTTP load balancer – Rust port of loadbalancer.py
//!
//! Stack:
//!   axum 0.7  – HTTP server
//!   heed 0.20 – embedded LMDB for CDN registry
//!   mongodb   – special-hash store (MONGO_URL)
//!   reqwest   – outbound HTTP (health checks, Arolinks, streaming proxy)
//!   dashmap   – lock-free concurrent rate-limiter map
//!
//! Module layout:
//!   config          – env-driven `Config`
//!   constants       – tunable ad-gating / token-TTL constants
//!   state           – `AppState`, `CdnPool`, `CdnMeta`, best-CDN cache
//!   link_kind       – shared /dl vs /watch discriminant
//!   lmdb_store      – LMDB CDN-registry CRUD
//!   mongo::*        – MongoDB-backed special hashes, CDN persistence, ad gating
//!   cdn_selection   – best-CDN pick (load ±1, IP dedup, cached)
//!   rate_limiter    – per-IP sliding window
//!   trusted_hosts   – CDN host whitelist + referer blocking (plgb only)
//!   admin_auth      – x-admin-key check
//!   health_check    – CDN health probe
//!   poller          – background health-check loop per pool
//!   proxy           – /watch streaming reverse-proxy + HTML rewrite
//!   http_utils      – shared redirect-response helper
//!   ads::*          – HMAC tokens, Arolinks calls, interstitial/message pages
//!   routes::*       – axum handlers, one file per route group

mod admin_auth;
mod ads;
mod cdn_selection;
mod config;
mod constants;
mod health_check;
mod http_utils;
mod link_kind;
mod lmdb_store;
mod mongo;
mod poller;
mod proxy;
mod rate_limiter;
mod routes;
mod state;
mod time_utils;
mod trusted_hosts;

use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use dotenvy::dotenv;
use heed::EnvOpenOptions;
use tokio::sync::RwLock;

use config::{numbered_env_values, Config};
use mongo::cdn_registry::{load_persisted_cdns, seed_cdns_from_env};
use mongo::special_hashes::load_special_hashes;
use poller::poller_task;
use routes::ad_tokens::{ad_tokens_callback, ad_tokens_entry, t_ad_tokens_callback, t_ad_tokens_entry};
use routes::cdn_admin::{add_cdn, add_cdn_telethon, reload_special};
use routes::dashboard::nitai;
use routes::health::health;
use routes::plgb_links::{dl, watch};
use routes::stats::stats;
use routes::telethon_links::{t_dl, t_wt};
use state::{AppState, BestCdnCache, CdnDb};
use trusted_hosts::rebuild_trusted_hosts;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    // Logging: set RUST_LOG=debug for verbose output, default is info
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = Arc::new(Config::from_env());

    // Validate required env vars – fail fast with a clear error message
    if config.admin_key.is_empty() {
        anyhow::bail!("LB_ADMIN_KEY env var is required but not set");
    }
    if config.enable_plgb && config.tg_redirect.is_empty() {
        anyhow::bail!("REDIRECT_TO env var is required but not set");
    }
    if !config.show_ads_plgb {
        tracing::warn!("LB_SHOW_ADS_PLGB is off - plgb ads are disabled");
    }
    if !config.show_ads_telethon {
        tracing::warn!("LB_SHOW_ADS_TELETHON is off - telethon-plgb ads are disabled");
    }
    if !config.enable_plgb && !config.enable_telethon {
        tracing::warn!("LB_ENABLE_PLGB and LB_ENABLE_TELETHON are both false - no CDN traffic will be routed");
    } else {
        if !config.enable_plgb {
            tracing::warn!("LB_ENABLE_PLGB is false - plgb CDN pool/routes disabled");
        }
        if !config.enable_telethon {
            tracing::warn!("LB_ENABLE_TELETHON is false - telethon-plgb CDN pool/routes disabled");
        }
    }
    if config.arolinks_api.is_none() {
        tracing::warn!("AROLINKS_API_TOKEN not set – one_ad and two_ad will fall back to direct Telegram redirect");
    }
    if std::env::var("LB_AD_SECRET").ok().filter(|s| !s.is_empty()).is_none() {
        tracing::warn!("LB_AD_SECRET not set – signing ad-callback tokens with LB_ADMIN_KEY (set LB_AD_SECRET for key separation)");
    }

    // ── Bind TCP listener EARLY so health checks pass during slow init ──
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8000);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Listening on {}", addr);

    // ── LMDB ──────────────────────────────────────────────────
    // LMDB uses a directory.  Create it if it doesn't exist.
    std::fs::create_dir_all("cdn.lmdb").ok();
    let env = Arc::new(unsafe {
        // SAFETY: we open this path exactly once in this process.
        EnvOpenOptions::new()
            .map_size(512 * 1024 * 1024) // 512 MB – same as Python
            .max_dbs(2) // one sub-db per CDN pool (plgb, telethon-plgb)
            .open("cdn.lmdb")?
    });

    // create_database is idempotent: opens existing DB or creates new one.
    let lmdb_db: CdnDb = {
        let mut wtxn = env.write_txn()?;
        let db = env.create_database(&mut wtxn, Some("cdns"))?;
        wtxn.commit()?;
        db
    };
    let lmdb_db_telethon: CdnDb = {
        let mut wtxn = env.write_txn()?;
        let db = env.create_database(&mut wtxn, Some("cdns_telethon"))?;
        wtxn.commit()?;
        db
    };

    // ── HTTP client (no global timeout – set per-request) ──────
    let http_client = reqwest::Client::builder()
        .user_agent("loadbalancer-rs/1.0")
        .build()?;

    // MongoDB for special hashes, CDN persistence, and per-user ad gating – MONGO_URL triggers all
    let (mongo_col, mongo_cdn_col, mongo_cdn_col_telethon, mongo_users_col): (
        Option<mongodb::Collection<mongodb::bson::Document>>,
        Option<mongodb::Collection<mongodb::bson::Document>>,
        Option<mongodb::Collection<mongodb::bson::Document>>,
        Option<mongodb::Collection<mongodb::bson::Document>>,
    ) = if let Ok(mongo_url) = std::env::var("MONGO_URL") {
        let db_name = std::env::var("MONGO_DB_NAME")
            .map_err(|_| anyhow::anyhow!("MONGO_DB_NAME env var is required when MONGO_URL is set"))?;
        let col_name = std::env::var("MONGO_DB_COLLECTION_NAME_PLGB")
            .map_err(|_| anyhow::anyhow!("MONGO_DB_COLLECTION_NAME_PLGB env var is required when MONGO_URL is set"))?;
        let users_col_name = std::env::var("MONGO_USERS_COLLECTION_NAME_PLGB")
            .unwrap_or_else(|_| "users".to_string());
        let mongo_client = mongodb::Client::with_uri_str(&mongo_url).await?;
        let db = mongo_client.database(&db_name);
        let special_col = db.collection::<mongodb::bson::Document>(&col_name);
        let cdn_col = db.collection::<mongodb::bson::Document>("cdn_registry");
        let cdn_col_telethon = db.collection::<mongodb::bson::Document>("cdn_registry_telethon");
        let users_col = db.collection::<mongodb::bson::Document>(&users_col_name);
        tracing::info!("Connected to MongoDB ({}.{}) for special hashes / file records", db_name, col_name);
        tracing::info!("Using MongoDB cdn_registry / cdn_registry_telethon collections for CDN persistence");
        tracing::info!("Using MongoDB '{}' collection for per-user ad gating", users_col_name);
        (Some(special_col), Some(cdn_col), Some(cdn_col_telethon), Some(users_col))
    } else {
        tracing::warn!("MONGO_URL not set – special hashes, CDN persistence, and ad gating disabled");
        (None, None, None, None)
    };

    // telethon-plgb ad gating: an entirely separate Mongo deployment from the
    // one above (MONGO_URL is plgb + LB-registry bookkeeping only). Mirrors
    // telethon-plgb's own MONGODB_URI/MONGODB_DBNAME/MONGODB_INDEX_URI[N] —
    // copy the same values here with the LB_MONGO_TELETHON_ prefix.
    let (mongo_users_col_telethon, mongo_user_files_cols_telethon): (
        Option<mongodb::Collection<mongodb::bson::Document>>,
        Vec<mongodb::Collection<mongodb::bson::Document>>,
    ) = if let Ok(uri) = std::env::var("LB_MONGO_TELETHON_URI") {
        let dbname = std::env::var("LB_MONGO_TELETHON_DBNAME").unwrap_or_else(|_| "TGFS".to_string());
        let primary_client = mongodb::Client::with_uri_str(&uri).await?;
        let primary_db = primary_client.database(&dbname);
        let users_col = primary_db.collection::<mongodb::bson::Document>("users");

        let index_uris = numbered_env_values("LB_MONGO_TELETHON_INDEX_URI");
        let mut user_files_cols = Vec::new();
        if index_uris.is_empty() {
            // No shard URIs configured → single shard, same as telethon-plgb's
            // own `_index_dbs = index_dbs or [primary]` fallback.
            user_files_cols.push(primary_db.collection::<mongodb::bson::Document>("user_files"));
        } else {
            for shard_uri in &index_uris {
                let client = mongodb::Client::with_uri_str(shard_uri).await?;
                user_files_cols.push(client.database(&dbname).collection::<mongodb::bson::Document>("user_files"));
            }
        }
        tracing::info!(
            "Connected to telethon-plgb MongoDB ({}.users) for ad gating ({} user_files shard(s))",
            dbname,
            user_files_cols.len()
        );
        (Some(users_col), user_files_cols)
    } else {
        tracing::warn!("LB_MONGO_TELETHON_URI not set – telethon-plgb ad gating disabled");
        (None, Vec::new())
    };

    // ── Build shared state ─────────────────────────────────────
    let state = AppState {
        lmdb_env: env,
        lmdb_db,
        lmdb_db_telethon,
        mongo_col,
        mongo_cdn_col,
        mongo_cdn_col_telethon,
        mongo_users_col,
        mongo_users_col_telethon,
        mongo_user_files_cols_telethon,
        special_hashes: Arc::new(DashMap::new()),
        best_cdn: Arc::new(RwLock::new(BestCdnCache::default())),
        best_cdn_telethon: Arc::new(RwLock::new(BestCdnCache::default())),
        rate_limiter: Arc::new(DashMap::new()),
        trusted_hosts: Arc::new(RwLock::new(HashSet::from([
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ]))),
        config,
        http_client,
    };

    // ── Load persisted CDNs from MongoDB, then seed from env vars (per pool) ──
    if state.config.enable_plgb {
        let loaded = load_persisted_cdns(&state, state::CdnPool::Plgb).await;
        tracing::info!("Loaded {} CDN(s) from MongoDB cdn_registry", loaded);
        seed_cdns_from_env(&state, state::CdnPool::Plgb, "LB_CDN_URLS").await;
    }
    if state.config.enable_telethon {
        let loaded_telethon = load_persisted_cdns(&state, state::CdnPool::Telethon).await;
        tracing::info!("Loaded {} CDN(s) from MongoDB cdn_registry_telethon", loaded_telethon);
        seed_cdns_from_env(&state, state::CdnPool::Telethon, "LB_CDN_URLS_TELETHON").await;
    }

    rebuild_trusted_hosts(&state).await;

    // Load special hashes from MongoDB on startup (non-blocking),
    // then re-sync every 5 minutes to pick up changes made by external apps.
    {
        let s = state.clone();
        tokio::spawn(async move {
            load_special_hashes(&s).await;
            loop {
                tokio::time::sleep(Duration::from_secs(1800)).await;
                load_special_hashes(&s).await;
            }
        });
    }

    // ── Background: CDN poller ────────────────────────────────
    // LMDB is local to each instance, so every instance must run its own
    // poller to keep CDN load/status data fresh.
    // Set IS_LEADER=0 to explicitly disable the poller on this instance.
    let is_leader = std::env::var("IS_LEADER")
        .map(|v| v != "0")
        .unwrap_or(true);

    if is_leader {
        if state.config.enable_plgb {
            let s = state.clone();
            tokio::spawn(poller_task(s, state::CdnPool::Plgb));
        }
        if state.config.enable_telethon {
            let s_telethon = state.clone();
            tokio::spawn(poller_task(s_telethon, state::CdnPool::Telethon));
        }
        tracing::info!(
            "CDN pollers started (plgb={}, telethon-plgb={})",
            state.config.enable_plgb,
            state.config.enable_telethon
        );
    } else {
        tracing::warn!("CDN pollers disabled (IS_LEADER=0)");
    }

    // ── Router ─────────────────────────────────────────────────
    let mut app = Router::new()
        .route("/health", get(health))
        .route("/nitai", get(nitai))
        .route("/reload_special", post(reload_special))
        .route("/ad-tokens/:user_id/:rand", get(ad_tokens_entry))
        .route("/ad-tokens/:user_id/:rand/:token", get(ad_tokens_callback))
        .route("/stats", get(stats));

    if state.config.enable_plgb {
        app = app
            .route("/add_cdn", post(add_cdn))
            .route("/dl/:hash/*filename", get(dl))
            .route("/watch/:hash/*filename", get(watch));
    }
    if state.config.enable_telethon {
        app = app
            .route("/add_cdn_telethon", post(add_cdn_telethon))
            .route("/t/dl/:payload/*rest", get(t_dl))
            .route("/t/wt/:payload/*rest", get(t_wt))
            .route("/t/ad-tokens/:user_id/:rand", get(t_ad_tokens_entry))
            .route("/t/ad-tokens/:user_id/:rand/:token", get(t_ad_tokens_callback));
    }

    let app = app.with_state(state);

    axum::serve(
        listener,
        // ConnectInfo extractor requires this wrapper
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
