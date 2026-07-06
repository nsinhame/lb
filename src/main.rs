//! Async HTTP load balancer – Rust port of loadbalancer.py
//!
//! Stack:
//!   axum 0.7  – HTTP server
//!   heed 0.20 – embedded LMDB for CDN registry
//!   mongodb   – special-hash store (MONGO_URL)
//!   reqwest   – outbound HTTP (health checks, Arolinks, streaming proxy)
//!   dashmap   – lock-free concurrent rate-limiter map

use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::Body,
    extract::{ConnectInfo, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use dotenvy::dotenv;
use heed::{Database, Env, EnvOpenOptions};
use hmac::{Hmac, Mac};
use rand::seq::SliceRandom;
use mongodb::bson::doc;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use tokio::sync::RwLock;
use tracing::debug;

/// A user is shown ads again once their last ad is older than this window.
/// Hard-coded to 2 days (in seconds) per product requirement.
const AD_INTERVAL_SECS: f64 = 2.0 * 24.0 * 60.0 * 60.0;

/// Ads are only shown to "established" users: their account must be at least
/// this old (by join_date) AND they must have generated at least
/// MIN_LINKS_FOR_ADS files. Newer / lighter users are never shown ads.
const ACCOUNT_AGE_MIN_SECS: f64 = 30.0 * 24.0 * 60.0 * 60.0; // 30 days
const MIN_LINKS_FOR_ADS: u64 = 30;

/// How long a signed ad-callback token stays valid (covers the arolinks
/// round-trip). After this it is rejected, preventing indefinite replay.
const AD_TOKEN_TTL_SECS: u64 = 60 * 60; // 1 hour

/// /ad-tokens "purchase" flow: users pre-watch ads to bank ad-free time.
/// Each ad grants 12h; users are blocked once they are banked > 1 day ahead
/// (so at most ~2 ads/day worth of ad-free time can be accumulated).
const ONE_DAY_SECS: f64 = 24.0 * 60.0 * 60.0;
const TWELVE_HOURS_SECS: f64 = 12.0 * 60.0 * 60.0;

type HmacSha256 = Hmac<Sha256>;

// ============================================================
// CONFIG
// ============================================================

struct Config {
    arolinks_api: Option<String>,
    arolinks_endpoint: String,
    admin_key: String,
    /// Secret used to HMAC-sign ad-callback tokens (falls back to admin_key).
    ad_secret: String,
    tg_redirect: String,
    max_requests_per_ip: usize,
    ttl_seconds: u64,
    poll_interval: u64,
    redirect_code: u16,
    fail_threshold: u64,
    referer_whitelist: HashSet<String>,
    best_cdn_ttl: Duration,
}

impl Config {
    fn from_env() -> Self {
        let poll_interval: u64 = std::env::var("LB_POLL_INTERVAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);

        // Same formula as Python: math.ceil((5 * 60) / POLL_INTERVAL)
        let fail_threshold = (((5 * 60) as f64) / poll_interval as f64).ceil() as u64;

        // Secret for signing ad-callback tokens. Falls back to the admin key so the
        // feature works out-of-the-box; set LB_AD_SECRET for proper key separation.
        let admin_key = std::env::var("LB_ADMIN_KEY").unwrap_or_default();
        let ad_secret = std::env::var("LB_AD_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| admin_key.clone());

        Config {
            arolinks_api: std::env::var("AROLINKS_API_TOKEN").ok(),
            arolinks_endpoint: "https://arolinks.com/api".to_string(),
            admin_key,
            ad_secret,
            tg_redirect: std::env::var("REDIRECT_TO").unwrap_or_default(),
            max_requests_per_ip: std::env::var("LB_MAX_REQUESTS_PER_IP")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
            ttl_seconds: std::env::var("LB_TTL_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(18000),
            poll_interval,
            redirect_code: std::env::var("LB_REDIRECT_CODE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(307),
            fail_threshold,
            referer_whitelist: std::env::var("LB_REFERER_WHITELIST")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            best_cdn_ttl: Duration::from_secs(poll_interval),
        }
    }
}

// ============================================================
// CDN METADATA (stored as JSON in LMDB)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CdnMeta {
    #[serde(default)]
    load: u64,
    /// 1 = online, 0 = offline
    #[serde(default)]
    last_ok: u8,
    #[serde(default)]
    fail_count: u64,
    #[serde(default)]
    updated_at: u64,
    #[serde(rename = "_ts", default)]
    ts: u64,
    /// Error description when offline (e.g. "timeout", "HTTP 503")
    #[serde(default)]
    error_code: String,
    /// Resolved IP address (used to deduplicate multi-URL CDNs)
    #[serde(default)]
    ip: String,
}

// ============================================================
// LMDB type alias
// keys  = &str  (CDN URL)
// values = &[u8] (JSON-encoded CdnMeta)
// ============================================================

type CdnDb = Database<heed::types::Str, heed::types::Bytes>;

// ============================================================
// BEST-CDN CACHE
// ============================================================

struct BestCdnCache {
    url: Option<String>,
    updated: Instant,
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

#[derive(Clone)]
struct AppState {
    lmdb_env: Arc<Env>,
    lmdb_db: CdnDb,
    /// MongoDB "file" collection: keyed by file `_id` (the URL hash). Holds
    /// `special_type` for some files and the owner `user_id` used for ad gating.
    /// (None if MONGO_URL not set)
    mongo_col: Option<mongodb::Collection<mongodb::bson::Document>>,
    /// MongoDB collection for CDN registry persistence (None if MONGO_URL not set)
    mongo_cdn_col: Option<mongodb::Collection<mongodb::bson::Document>>,
    /// MongoDB "users" collection: docs keyed by `id` (= file's `user_id`) and
    /// holding `ad_watch_time`. (None if MONGO_URL not set)
    mongo_users_col: Option<mongodb::Collection<mongodb::bson::Document>>,
    /// key = file hash, value = special_type ("zero_ad", "one_ad", "two_ad", …)
    special_hashes: Arc<DashMap<String, String>>,
    best_cdn: Arc<RwLock<BestCdnCache>>,
    /// key = "ip:hash", value = list of request timestamps
    rate_limiter: Arc<DashMap<String, Vec<Instant>>>,
    trusted_hosts: Arc<RwLock<HashSet<String>>>,
    config: Arc<Config>,
    http_client: Client,
}

// ============================================================
// LMDB HELPERS  (all I/O wrapped in spawn_blocking)
// ============================================================

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn lmdb_set_cdn(state: &AppState, url: String, mut meta: CdnMeta) {
    meta.ts = now_unix();
    let env = state.lmdb_env.clone();
    let db = state.lmdb_db;
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

async fn lmdb_delete_cdn(state: &AppState, url: String) {
    let env = state.lmdb_env.clone();
    let db = state.lmdb_db;
    let _ = tokio::task::spawn_blocking(move || -> heed::Result<()> {
        let mut wtxn = env.write_txn()?;
        db.delete(&mut wtxn, url.as_str())?;
        wtxn.commit()
    })
    .await;
}

async fn lmdb_get_cdn(state: &AppState, url: String) -> Option<CdnMeta> {
    let env = state.lmdb_env.clone();
    let db = state.lmdb_db;
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

async fn lmdb_list_cdns(state: &AppState) -> Vec<(String, CdnMeta)> {
    let env = state.lmdb_env.clone();
    let db = state.lmdb_db;
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

// ============================================================
// TRUSTED HOSTS  (CDN hostnames + loopback)
// ============================================================

async fn rebuild_trusted_hosts(state: &AppState) {
    let cdns = lmdb_list_cdns(state).await;
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
// SPECIAL HASHES  (MongoDB only)
// ============================================================

/// Full sync from MongoDB into the in-memory DashMap.
/// Uses a streaming cursor so there is NO timeout: 200k+ docs will all be
/// loaded, as long as MongoDB keeps sending data.  The old map contents are
/// replaced atomically only after the cursor is exhausted, so in-flight
/// requests always see a consistent snapshot.
async fn load_special_hashes(state: &AppState) {
    let Some(col) = &state.mongo_col else {
        return; // MongoDB not configured – nothing to do
    };
    match col.find(None, None).await {
        Ok(mut cursor) => {
            let mut fresh: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            loop {
                match cursor.advance().await {
                    Ok(true) => {
                        if let Ok(doc) = cursor.deserialize_current() {
                            let id = doc
                                .get_object_id("_id")
                                .map(|oid| oid.to_hex())
                                .or_else(|_| doc.get_str("_id").map(|s| s.to_string()));
                            let stype = doc.get_str("special_type").map(|s| s.to_string());
                            if let (Ok(id), Ok(stype)) = (id, stype) {
                                fresh.insert(id, stype);
                            }
                        }
                    }
                    _ => break,
                }
            }
            // Swap in the fresh snapshot atomically
            state.special_hashes.retain(|k, _| fresh.contains_key(k.as_str()));
            for (k, v) in fresh {
                state.special_hashes.insert(k, v);
            }
            debug!("Loaded {} special hashes from MongoDB", state.special_hashes.len());
        }
        Err(e) => tracing::error!("MongoDB error loading special hashes: {}", e),
    }
}

// ============================================================
// CDN REGISTRY PERSISTENCE  (MongoDB cdn_registry collection)
// ============================================================

/// Upsert a CDN URL into the MongoDB cdn_registry collection.
async fn mongo_add_cdn(state: &AppState, url: &str) {
    let Some(col) = &state.mongo_cdn_col else { return };
    let filter = doc! { "_id": url };
    let update = doc! { "$setOnInsert": { "_id": url } };
    let opts = mongodb::options::UpdateOptions::builder().upsert(true).build();
    if let Err(e) = col.update_one(filter, update, opts).await {
        tracing::warn!("MongoDB cdn_registry upsert error for {}: {}", url, e);
    }
}

/// Remove a CDN URL from the MongoDB cdn_registry collection.
async fn mongo_remove_cdn(state: &AppState, url: &str) {
    let Some(col) = &state.mongo_cdn_col else { return };
    if let Err(e) = col.delete_one(doc! { "_id": url }, None).await {
        tracing::warn!("MongoDB cdn_registry delete error for {}: {}", url, e);
    }
}

// ============================================================
// PER-USER AD GATING  (file collection → users collection)
// ============================================================

/// Current wall-clock time as fractional Unix seconds (e.g. 1783243342.2778153).
fn now_unix_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Coerce a BSON value that may be Long/Int/Double/String into i64.
fn bson_to_i64(v: Option<&mongodb::bson::Bson>) -> Option<i64> {
    use mongodb::bson::Bson;
    match v? {
        Bson::Int64(n) => Some(*n),
        Bson::Int32(n) => Some(*n as i64),
        Bson::Double(f) => Some(*f as i64),
        Bson::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Coerce a BSON value that may be Double/Long/Int/String into f64.
fn bson_to_f64(v: Option<&mongodb::bson::Bson>) -> Option<f64> {
    use mongodb::bson::Bson;
    match v? {
        Bson::Double(f) => Some(*f),
        Bson::Int64(n) => Some(*n as f64),
        Bson::Int32(n) => Some(*n as f64),
        Bson::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Look up a file's owner `user_id` in the file collection, keyed by the URL hash
/// (which is the document `_id` — an ObjectId hex, or a plain string fallback).
async fn file_user_id(state: &AppState, hash: &str) -> Option<i64> {
    let col = state.mongo_col.as_ref()?;
    let filter = match mongodb::bson::oid::ObjectId::parse_str(hash) {
        Ok(oid) => doc! { "_id": oid },
        Err(_) => doc! { "_id": hash },
    };
    let file_doc = col.find_one(filter, None).await.ok()??;
    bson_to_i64(file_doc.get("user_id"))
}

/// True if the user has generated at least `min` links (docs in the file
/// collection with this `user_id`). Uses an aggregation with `$limit` so the
/// scan stops at `min` entries; the existing `{ user_id: 1, ... }` index prefix
/// keeps the `$match` index-only, so no dedicated index is required. On error
/// returns false (fail-safe: the user then looks "new", so no ads are shown).
async fn user_has_min_files(state: &AppState, user_id: i64, min: u64) -> bool {
    let Some(col) = state.mongo_col.as_ref() else {
        return false;
    };
    let pipeline = vec![
        doc! { "$match": { "user_id": user_id } },
        doc! { "$limit": min as i64 },
        doc! { "$count": "n" },
    ];
    match col.aggregate(pipeline, None).await {
        Ok(mut cursor) => match cursor.advance().await {
            // $count emits { n } only when at least one doc matched; with the
            // $limit above, n == min exactly when the user has >= min files.
            Ok(true) => cursor
                .deserialize_current()
                .ok()
                .and_then(|d| bson_to_i64(d.get("n")))
                .map(|n| n >= min as i64)
                .unwrap_or(false),
            _ => false, // no matching files
        },
        Err(e) => {
            tracing::warn!("file count aggregate error for user {}: {}", user_id, e);
            false
        }
    }
}

/// Decide whether the user who owns `hash` should be shown an ad.
///
/// Only "established" users see ads — they must be at least 30 days old (by
/// join_date) AND have generated at least MIN_LINKS_FOR_ADS links (file docs).
/// For eligible users the usual ad_watch_time gate then applies:
///   * ad_watch_time older than AD_INTERVAL_SECS (2 days)  → show ads
///   * ad_watch_time field missing on an existing user doc → show ads
/// Anything unresolvable (Mongo off, user/user_id/join_date missing, too new,
/// too few links, or a query error) → serve directly (loop-safe: guarantees the
/// post-ad callback can't re-trigger ads).
async fn should_show_ads(state: &AppState, hash: &str) -> bool {
    let Some(users) = state.mongo_users_col.as_ref() else {
        return false;
    };
    let Some(uid) = file_user_id(state, hash).await else {
        return false;
    };

    let user_doc = match users.find_one(doc! { "id": uid }, None).await {
        Ok(Some(doc)) => doc,
        Ok(None) => return false, // no user doc → serve (loop-safe)
        Err(e) => {
            tracing::warn!("users lookup error for id {}: {}", uid, e);
            return false;
        }
    };

    let now = now_unix_f64();

    // Established-user gate 1: account at least 30 days old.
    match bson_to_f64(user_doc.get("join_date")) {
        Some(joined) if now - joined >= ACCOUNT_AGE_MIN_SECS => {}
        _ => return false, // too new, or join_date missing/unreadable → no ads
    }

    // Established-user gate 2: at least 30 generated links.
    if !user_has_min_files(state, uid, MIN_LINKS_FOR_ADS).await {
        return false;
    }

    // Established user → apply the ad_watch_time gate.
    match bson_to_f64(user_doc.get("ad_watch_time")) {
        Some(t) => (now - t) > AD_INTERVAL_SECS,
        None => true, // field absent → show ads
    }
}

/// Record that the user who owns `hash` just watched an ad (ad_watch_time = now).
async fn update_ad_watch_time(state: &AppState, hash: &str) {
    let Some(users) = state.mongo_users_col.as_ref() else {
        return;
    };
    let Some(uid) = file_user_id(state, hash).await else {
        return;
    };
    let filter = doc! { "id": uid };
    let update = doc! { "$set": { "ad_watch_time": now_unix_f64() } };
    if let Err(e) = users.update_one(filter, update, None).await {
        tracing::warn!("Failed to update ad_watch_time for user {}: {}", uid, e);
    }
}

/// Read a user's ad_watch_time directly by `id`. Returns:
///   Some(Some(t)) = user found with ad_watch_time,
///   Some(None)    = user found without it, or user not found,
///   None          = users collection unavailable / query failed.
async fn user_ad_watch_time_by_id(state: &AppState, user_id: i64) -> Option<Option<f64>> {
    let users = state.mongo_users_col.as_ref()?;
    match users.find_one(doc! { "id": user_id }, None).await {
        Ok(Some(user_doc)) => Some(bson_to_f64(user_doc.get("ad_watch_time"))),
        Ok(None) => Some(None),
        Err(e) => {
            tracing::warn!("users lookup error for id {}: {}", user_id, e);
            None
        }
    }
}

/// Set a user's ad_watch_time to an absolute value (upserts the user doc).
async fn set_ad_watch_time(state: &AppState, user_id: i64, value: f64) -> bool {
    let Some(users) = state.mongo_users_col.as_ref() else {
        return false;
    };
    let filter = doc! { "id": user_id };
    let update = doc! { "$set": { "ad_watch_time": value } };
    let opts = mongodb::options::UpdateOptions::builder().upsert(true).build();
    match users.update_one(filter, update, opts).await {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!("Failed to set ad_watch_time for user {}: {}", user_id, e);
            false
        }
    }
}

// ============================================================
// CDN SELECTION
// ============================================================


async fn get_best_cdn(state: &AppState) -> Option<String> {
    // Return cached value if still fresh
    {
        let cache = state.best_cdn.read().await;
        if let Some(ref url) = cache.url {
            if cache.updated.elapsed() < state.config.best_cdn_ttl {
                return Some(url.clone());
            }
        }
    }

    let cdns = lmdb_list_cdns(state).await;

    // Deduplicate by IP: if two URLs resolve to the same server, only count once.
    // For each IP group, keep the URL with the lowest load.
    let mut ip_best: std::collections::HashMap<String, (String, u64)> =
        std::collections::HashMap::new();
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

    let chosen = candidates
        .choose(&mut rand::thread_rng())
        .cloned()?;

    // Cache the result
    {
        let mut cache = state.best_cdn.write().await;
        cache.url = Some(chosen.clone());
        cache.updated = Instant::now();
    }

    Some(chosen)
}

// ============================================================
// RATE LIMITER  (in-process sliding window, per IP:hash)
// ============================================================

fn record_ip(state: &AppState, ip: &str, hash: &str) -> usize {
    let key = format!("{}:{}", ip, hash);
    let ttl = Duration::from_secs(state.config.ttl_seconds);
    let now = Instant::now();
    let mut entry = state.rate_limiter.entry(key).or_default();
    entry.retain(|&t| now.duration_since(t) < ttl);
    entry.push(now);
    entry.len()
}

// ============================================================
// REFERER BLOCKING
// ============================================================

async fn referer_blocked(state: &AppState, headers: &HeaderMap, ip: &str) -> bool {
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

// ============================================================
// ADMIN KEY CHECK
// ============================================================

fn check_admin(headers: &HeaderMap, config: &Config) -> Result<(), Response> {
    let key = headers
        .get("x-admin-key")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if key != config.admin_key {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"detail": "unauthorized"})),
        )
            .into_response());
    }
    Ok(())
}

// ============================================================
// AD-REDIRECT / AROLINKS
// ============================================================

async fn arolinks_shorten(client: &Client, api: &str, endpoint: &str, raw_url: &str) -> Option<String> {
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

// ============================================================
// SPECIAL-TYPE REDIRECT  (zero_ad / one_ad / two_ad)
// ============================================================

async fn handle_special_redirect(state: &AppState, special_type: &str) -> Response {
    let tg = state.config.tg_redirect.clone();

    match special_type {
        // zero_ad: no ads – go straight to the Telegram bot
        "zero_ad" => axum::response::Redirect::to(&tg).into_response(),

        // one_ad: one Arolinks ad, destination is the Telegram bot
        "one_ad" => {
            if let Some(api) = &state.config.arolinks_api {
                if let Some(short) =
                    arolinks_shorten(&state.http_client, api, &state.config.arolinks_endpoint, &tg).await
                {
                    return axum::response::Redirect::to(&short).into_response();
                }
            }
            axum::response::Redirect::to(&tg).into_response()
        }

        // two_ad: two chained Arolinks ads; second ad leads to Telegram bot
        "two_ad" => {
            if let Some(api) = &state.config.arolinks_api {
                if let Some(short2) =
                    arolinks_shorten(&state.http_client, api, &state.config.arolinks_endpoint, &tg).await
                {
                    if let Some(short1) =
                        arolinks_shorten(&state.http_client, api, &state.config.arolinks_endpoint, &short2).await
                    {
                        return axum::response::Redirect::to(&short1).into_response();
                    }
                    // Second shorten failed – degrade to one ad
                    return axum::response::Redirect::to(&short2).into_response();
                }
            }
            axum::response::Redirect::to(&tg).into_response()
        }

        // Unknown type – fall back to Telegram bot
        _ => axum::response::Redirect::to(&tg).into_response(),
    }
}

// ============================================================
// AROLINKS AD REDIRECT HELPERS
// ============================================================

/// Low-level: hex-encoded HMAC-SHA256 of `message` under `secret`.
fn hmac_hex(secret: &str, message: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any size");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Low-level: constant-time check that `sig_hex` is a valid HMAC of `message`.
fn hmac_verify(secret: &str, message: &str, sig_hex: &str) -> bool {
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(message.as_bytes());
    mac.verify_slice(&sig_bytes).is_ok()
}

/// Split a `<exp>-<sig>` token, rejecting it if the expiry has already passed.
fn parse_signed_token(token: &str) -> Option<(u64, &str)> {
    let (exp_str, sig_hex) = token.split_once('-')?;
    let exp = exp_str.parse::<u64>().ok()?;
    if now_unix() > exp {
        return None; // expired
    }
    Some((exp, sig_hex))
}

/// Canonical string the /dl and /watch ad-callback signature is computed over.
/// Binding kind, hash, filename and expiry means a token is valid only for that link.
fn ad_token_canonical(kind: LinkKind, hash: &str, filename: &str, exp: u64) -> String {
    format!("{}:{}:{}:{}", kind.path(), hash, filename, exp)
}

/// Produce a tamper-proof /dl|/watch callback token `<exp>-<hex hmac-sha256>`.
fn sign_ad_token(secret: &str, kind: LinkKind, hash: &str, filename: &str, exp: u64) -> String {
    format!(
        "{}-{}",
        exp,
        hmac_hex(secret, &ad_token_canonical(kind, hash, filename, exp))
    )
}

/// Cheap structural check: does this path segment look like an ad token
/// (`<digits>-<64 hex chars>`)? Real filenames won't match this shape.
fn looks_like_ad_token(seg: &str) -> bool {
    match seg.split_once('-') {
        Some((exp, sig)) => {
            !exp.is_empty()
                && exp.bytes().all(|b| b.is_ascii_digit())
                && sig.len() == 64
                && sig.bytes().all(|b| b.is_ascii_hexdigit())
        }
        None => false,
    }
}

/// Verify a /dl|/watch callback token (signature match + not expired).
fn verify_ad_token(secret: &str, kind: LinkKind, hash: &str, filename: &str, token: &str) -> bool {
    match parse_signed_token(token) {
        Some((exp, sig_hex)) => {
            hmac_verify(secret, &ad_token_canonical(kind, hash, filename, exp), sig_hex)
        }
        None => false,
    }
}

/// Canonical string for the /ad-tokens purchase callback (binds the user id).
fn purchase_canonical(user_id: i64, exp: u64) -> String {
    format!("ad-tokens:{}:{}", user_id, exp)
}

/// Produce a tamper-proof /ad-tokens callback token bound to `user_id`.
fn sign_purchase_token(secret: &str, user_id: i64, exp: u64) -> String {
    format!("{}-{}", exp, hmac_hex(secret, &purchase_canonical(user_id, exp)))
}

/// Verify an /ad-tokens callback token (signature match + not expired).
fn verify_purchase_token(secret: &str, user_id: i64, token: &str) -> bool {
    match parse_signed_token(token) {
        Some((exp, sig_hex)) => hmac_verify(secret, &purchase_canonical(user_id, exp), sig_hex),
        None => false,
    }
}

/// Reconstruct the public base URL (scheme://host) the client originally hit,
/// so the arolinks destination points back at this load balancer.
fn public_base_url(headers: &HeaderMap) -> Option<String> {
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
/// `<base>/<kind>/<hash>/<token>/<filename>`.  Returns None when an ad cannot
/// be built (arolinks unconfigured, Host missing, or the shorten call failed)
/// so the caller can serve the content directly instead.
async fn ad_redirect(
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
    Some(axum::response::Redirect::to(&short).into_response())
}

async fn nitai() -> impl IntoResponse {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Nitai – Load Balancer Dashboard</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
  header{background:linear-gradient(135deg,#1a1f2e,#252d3d);padding:20px 32px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #2d3748}
  header h1{font-size:1.6rem;font-weight:700;color:#63b3ed;letter-spacing:.5px}
  header h1 span{color:#68d391}
  #status-bar{font-size:.8rem;color:#718096;display:flex;align-items:center;gap:8px}
  #dot{width:8px;height:8px;border-radius:50%;background:#68d391;animation:pulse 2s infinite}
  @keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
  main{padding:24px 32px;display:grid;gap:20px}
  .row{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
  .card{background:#1a1f2e;border:1px solid #2d3748;border-radius:12px;padding:20px}
  .card h2{font-size:.75rem;text-transform:uppercase;letter-spacing:1px;color:#718096;margin-bottom:12px}
  .stat-val{font-size:2rem;font-weight:700;color:#63b3ed}
  .stat-sub{font-size:.78rem;color:#718096;margin-top:4px}
  #best-cdn-val{font-size:1rem;word-break:break-all;color:#68d391;margin-top:6px;font-weight:600}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  th{text-align:left;padding:10px 12px;color:#718096;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.8px;border-bottom:1px solid #2d3748}
  td{padding:10px 12px;border-bottom:1px solid #1e2535;vertical-align:middle}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:#252d3d}
  .badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:.72rem;font-weight:600}
  .online{background:#1c4532;color:#68d391}
  .offline{background:#742a2a;color:#fc8181}
  .load-bar-wrap{background:#2d3748;border-radius:4px;height:8px;width:120px;overflow:hidden}
  .load-bar{height:100%;border-radius:4px;background:linear-gradient(90deg,#63b3ed,#4299e1);transition:width .4s}
  .load-bar.warn{background:linear-gradient(90deg,#f6ad55,#ed8936)}
  .load-bar.danger{background:linear-gradient(90deg,#fc8181,#e53e3e)}
  .section-title{font-size:.95rem;font-weight:600;color:#a0aec0;margin-bottom:10px}
  .empty{color:#4a5568;font-style:italic;font-size:.85rem;padding:12px 0}
  .trusted-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px}
  .trusted-chip{background:#1a365d;color:#90cdf4;border-radius:6px;padding:3px 10px;font-size:.78rem;font-family:monospace}
  .cdn-link{display:block;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#63b3ed;text-decoration:none;cursor:pointer}
  .cdn-link:hover{text-decoration:underline;color:#90cdf4}
  @media(max-width:600px){main{padding:16px};header{padding:16px}}
</style>
</head>
<body>
<header>
  <h1>⚡ Nitai <span>Dashboard</span></h1>
  <div id="status-bar"><div id="dot"></div><span id="last-update">Loading…</span></div>
</header>
<main>
  <div class="row" id="summary-cards">
    <div class="card"><h2>Total CDNs</h2><div class="stat-val" id="total-cdns">–</div><div class="stat-sub">registered</div></div>
    <div class="card"><h2>Online CDNs</h2><div class="stat-val" id="online-cdns" style="color:#68d391">–</div><div class="stat-sub">responding</div></div>
    <div class="card"><h2>Offline CDNs</h2><div class="stat-val" id="offline-cdns" style="color:#fc8181">–</div><div class="stat-sub">unreachable</div></div>
    <div class="card"><h2>Total Load</h2><div class="stat-val" id="total-load">–</div><div class="stat-sub">active connections</div></div>
    <div class="card"><h2>Best CDN</h2><div id="best-cdn-val">–</div><div class="stat-sub">current selection</div></div>
  </div>

  <div class="card">
    <div class="section-title">CDN Registry</div>
    <table>
      <thead><tr><th>URL</th><th>Status</th><th>Load</th><th>Load Bar</th><th>Fail Count</th><th>Last Updated</th></tr></thead>
      <tbody id="cdn-table-body"><tr><td colspan="6" class="empty">Loading…</td></tr></tbody>
    </table>
  </div>

  <div class="card">
    <div class="section-title">Trusted Hosts</div>
    <div class="trusted-list" id="trusted-list"></div>
  </div>
</main>

<script>
const REFRESH_MS = 5000;

function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString();
}

function loadColor(load) {
  if (load >= 99999) return 'danger';
  if (load > 20) return 'warn';
  return '';
}

function loadBarWidth(load) {
  if (load >= 99999) return 100;
  return Math.min(100, Math.round((load / 50) * 100));
}

const ADMIN_KEY = new URLSearchParams(location.search).get('key') || '';

// If no key in URL, show a login overlay instead of silently failing
if (!ADMIN_KEY) {
  document.addEventListener('DOMContentLoaded', () => {
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;background:#0f1117;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;z-index:999';
    overlay.innerHTML = `
      <h2 style="color:#63b3ed;font-size:1.4rem">⚡ Nitai Dashboard</h2>
      <p style="color:#718096;font-size:.9rem">Enter your admin key to continue</p>
      <input id="key-input" type="password" placeholder="LB_ADMIN_KEY" style="background:#1a1f2e;border:1px solid #2d3748;color:#e2e8f0;border-radius:8px;padding:10px 16px;font-size:1rem;width:300px;outline:none">
      <button onclick="const k=document.getElementById('key-input').value;if(k)location.search='?key='+encodeURIComponent(k)" style="background:#2b6cb0;color:#fff;border:none;border-radius:8px;padding:10px 24px;font-size:1rem;cursor:pointer">Open Dashboard</button>
    `;
    document.body.appendChild(overlay);
    document.getElementById('key-input').addEventListener('keydown', e => {
      if (e.key === 'Enter') { const k = e.target.value; if(k) location.search='?key='+encodeURIComponent(k); }
    });
  });
}

async function fetchStats() {
  try {
    const r = await fetch('/stats', { headers: { 'x-admin-key': ADMIN_KEY } });
    if (r.status === 401) return { __error: 401 };
    if (!r.ok) return { __error: r.status };
    return await r.json();
  } catch(e) {
    return { __error: 0 };
  }
}

function render(data) {
  if (!data || data.__error !== undefined) {
    const code = data && data.__error;
    const msg = code === 401 ? 'Wrong admin key – check ?key= in URL'
               : code === 0  ? 'Cannot reach server'
               : 'Server error ' + code;
    document.getElementById('last-update').textContent = msg;
    document.getElementById('dot').style.background = '#fc8181';
    return;
  }
  document.getElementById('dot').style.background = '#68d391';
  document.getElementById('last-update').textContent = 'Updated ' + new Date().toLocaleTimeString();

  const cdns = data.cdns || [];
  const online = cdns.filter(c => c.last_ok === 1);
  const offline = cdns.filter(c => c.last_ok !== 1);
  const seenIps = new Set();
  const totalLoad = online.reduce((s, c) => {
    const key = c.ip || c.url;
    if (seenIps.has(key)) return s;
    seenIps.add(key);
    return s + (c.load < 99999 ? c.load : 0);
  }, 0);

  document.getElementById('total-cdns').textContent = cdns.length;
  document.getElementById('online-cdns').textContent = online.length;
  document.getElementById('offline-cdns').textContent = offline.length;
  document.getElementById('total-load').textContent = totalLoad;

  const best = data.best_cdn;
  const bestEl = document.getElementById('best-cdn-val');
  if (best) {
    const host = (() => { try { return new URL(best).hostname; } catch(e) { return best; }})();
    bestEl.textContent = host;
    bestEl.title = best;
  } else {
    bestEl.textContent = 'None';
    bestEl.style.color = '#fc8181';
  }

  // CDN table
  const tbody = document.getElementById('cdn-table-body');
  if (cdns.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">No CDNs registered</td></tr>';
  } else {
    tbody.innerHTML = cdns.map(c => {
      const host = (() => { try { return new URL(c.url).hostname; } catch(e) { return c.url; }})();
      const statusUrl = (c.url.startsWith('http') ? c.url : 'https://' + c.url) + '/status';
      const lc = loadColor(c.load);
      const bw = loadBarWidth(c.load);
      const loadDisp = c.load >= 99999 ? '∞' : c.load;
      return `<tr>
        <td onclick="window.open('${statusUrl}','_blank')" style="cursor:pointer;color:#63b3ed;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${statusUrl}">${host} ↗</td>
        <td><span class="badge ${c.last_ok === 1 ? 'online' : 'offline'}">${c.last_ok === 1 ? 'Online' : 'Offline'}</span>${c.last_ok !== 1 && c.error_code ? `<br><span style="font-size:.75rem;color:#fc8181">${c.error_code}</span>` : ''}</td>
        <td>${loadDisp}</td>
        <td><div class="load-bar-wrap"><div class="load-bar ${lc}" style="width:${bw}%"></div></div></td>
        <td>${c.fail_count}</td>
        <td>${fmtTime(c.updated_at)}</td>
      </tr>`;
    }).join('');
  }

  // Trusted hosts
  const trusted = data.trusted_hosts || [];
  document.getElementById('trusted-list').innerHTML =
    trusted.map(h => `<span class="trusted-chip">${h}</span>`).join('');
}

async function refresh() {
  const data = await fetchStats();
  try { render(data); } catch(e) { console.error('render error:', e); }
  setTimeout(refresh, REFRESH_MS);
}

refresh();
</script>
</body>
</html>"#;
    Html(html)
}



fn fix_video_src(html: &str, hash: &str, filename: &str) -> String {
    let escaped = regex::escape(hash);
    // The `regex` crate does not support lookaheads, so we use a capture group
    // instead: match /dl/<hash> followed by any non-slash character and capture
    // that character so we can put it back in the replacement.
    // This is idempotent: /dl/<hash>/<filename> won't match because the char
    // immediately after <hash> is '/', which is excluded by [^/].
    let pattern = format!(r"/dl/{}([^/])", escaped);
    match Regex::new(&pattern) {
        Ok(re) => re
            .replace_all(html, format!("/dl/{}/{}$1", hash, filename).as_str())
            .into_owned(),
        Err(_) => html.to_string(),
    }
}

// ============================================================
// CDN HEALTH CHECK
// ============================================================

/// Resolve the first IP address for a CDN URL (best-effort, returns empty string on failure).
async fn resolve_cdn_ip(url: &str) -> String {
    let Ok(parsed) = url::Url::parse(url) else { return String::new() };
    let Some(host) = parsed.host_str() else { return String::new() };
    let port = parsed.port_or_known_default().unwrap_or(80);
    let Ok(mut addrs) = tokio::net::lookup_host(format!("{}:{}", host, port)).await else {
        return String::new();
    };
    addrs.next().map(|a| a.ip().to_string()).unwrap_or_default()
}

/// Returns (url, ok, load, error_code, ip)
async fn check_cdn_health(client: Client, url: String) -> (String, bool, u64, String, String) {
    let ip = resolve_cdn_ip(&url).await;
    let result = client
        .get(format!("{}/status", url))
        .timeout(Duration::from_secs(3))
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                return (url, false, 99999, format!("HTTP {}", status.as_u16()), ip);
            }
            match resp.json::<Value>().await {
                Ok(js) => {
                    let total: u64 = js
                        .get("loads")
                        .and_then(|l| l.as_object())
                        .map(|m| m.values().filter_map(|v| v.as_u64()).sum())
                        .unwrap_or(99999);
                    (url, true, total, String::new(), ip)
                }
                Err(_) => (url, false, 99999, "invalid response".to_string(), ip),
            }
        }
        Err(e) => {
            let err = if e.is_timeout() {
                "timeout".to_string()
            } else {
                "no response".to_string()
            };
            (url, false, 99999, err, ip)
        }
    }
}

// ============================================================
// CDN POLLER (runs only on the leader instance)
// ============================================================

async fn poller_task(state: AppState) {
    let interval = Duration::from_secs(state.config.poll_interval);
    loop {
        let cdns = lmdb_list_cdns(&state).await;

        // Fan-out: check all CDNs concurrently
        let mut handles = Vec::with_capacity(cdns.len());
        for (url, _) in &cdns {
            let client = state.http_client.clone();
            let url = url.clone();
            handles.push(tokio::spawn(check_cdn_health(client, url)));
        }

        // Build a lookup map for previous fail counts
        let prev_map: std::collections::HashMap<String, CdnMeta> =
            cdns.into_iter().collect();

        for handle in handles {
            let Ok((url, ok, load, error_code, ip)) = handle.await else {
                continue;
            };
            let prev_fail = prev_map
                .get(&url)
                .map(|m| m.fail_count)
                .unwrap_or(0);

            if ok {
                lmdb_set_cdn(
                    &state,
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
                    mongo_remove_cdn(&state, &url).await;
                    lmdb_delete_cdn(&state, url).await;
                } else {
                    lmdb_set_cdn(
                        &state,
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

        rebuild_trusted_hosts(&state).await;

        // Invalidate best-CDN cache so next request re-evaluates with fresh loads
        {
            let mut cache = state.best_cdn.write().await;
            cache.url = None;
            cache.updated = Instant::now() - Duration::from_secs(9999);
        }

        tokio::time::sleep(interval).await;
    }
}

// ============================================================
// STREAMING PROXY  (used by /watch)
// ============================================================

async fn stream_upstream(
    client: &Client,
    upstream_url: &str,
    mut req_headers: HeaderMap,
    hash: &str,
    filename: &str,
) -> Result<Response, StatusCode> {
    req_headers.remove(header::HOST);
    // Remove Accept-Encoding so the CDN returns uncompressed HTML we can parse and rewrite.
    // Without this, the CDN may return gzip-encoded bytes that look like garbage to fix_video_src.
    req_headers.remove(header::ACCEPT_ENCODING);

    let resp = client
        .get(upstream_url)
        .headers(req_headers)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let upstream_status = resp.status();
    let upstream_headers = resp.headers().clone();

    let content_type = upstream_headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Hop-by-hop headers must NOT be forwarded to the client.
    // Forwarding Transfer-Encoding: chunked causes double-encoding: reqwest already
    // decodes the upstream chunking, so axum/hyper applies its own chunking on top.
    // Envoy then sees a malformed body and resets the connection before sending headers.
    let is_hop_by_hop = |name: &str| {
        matches!(
            name,
            "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "te"
                | "trailers"
                | "upgrade"
                | "proxy-authenticate"
                | "proxy-authorization"
        )
    };

    if content_type.contains("text/html") {
        // Buffer the HTML, rewrite video src, then send
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let html = String::from_utf8_lossy(&body_bytes);
        let fixed = fix_video_src(&html, hash, filename);
        let fixed_bytes = fixed.into_bytes();

        let mut builder = axum::http::Response::builder().status(upstream_status);
        for (k, v) in &upstream_headers {
            let name = k.as_str().to_lowercase();
            // Skip hop-by-hop headers AND Content-Length: the body changed after
            // fix_video_src, so the upstream length is now wrong.
            if name == "content-length" || is_hop_by_hop(&name) {
                continue;
            }
            builder = builder.header(k, v);
        }
        // Set correct Content-Length for the rewritten body.
        builder = builder.header(header::CONTENT_LENGTH, fixed_bytes.len());
        Ok(builder
            .body(Body::from(fixed_bytes))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
    } else {
        // Stream bytes directly to the client without buffering
        // reqwest::Error: Into<BoxError> via std blanket impl, so no .map_err needed
        let body = Body::from_stream(resp.bytes_stream());

        let mut builder = axum::http::Response::builder().status(upstream_status);
        for (k, v) in &upstream_headers {
            let name = k.as_str().to_lowercase();
            if is_hop_by_hop(&name) {
                continue;
            }
            builder = builder.header(k, v);
        }
        Ok(builder
            .body(body)
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
    }
}

// ============================================================
// PATH EXTRACTOR  (shared by /dl and /watch)
// ============================================================

#[derive(Deserialize)]
struct HashFilePath {
    hash: String,
    filename: String,
}

// ============================================================
// ROUTE HANDLERS
// ============================================================

async fn health() -> &'static str {
    "ok"
}

async fn add_cdn(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Json(body): axum::extract::Json<Value>,
) -> Response {
    if let Err(e) = check_admin(&headers, &state.config) {
        return e;
    }
    let mut added = Vec::new();
    if let Some(urls) = body.get("urls").and_then(|u| u.as_array()) {
        for u in urls {
            if let Some(url_str) = u.as_str() {
                let url = url_str.trim_end_matches('/').to_string();
                if url.starts_with("http")
                    && lmdb_get_cdn(&state, url.clone()).await.is_none()
                {
                    lmdb_set_cdn(
                        &state,
                        url.clone(),
                        CdnMeta {
                            load: 99999,
                            last_ok: 0,
                            fail_count: 0,
                            ..Default::default()
                        },
                    )
                    .await;
                    mongo_add_cdn(&state, &url).await;
                    added.push(url);
                }
            }
        }
    }
    rebuild_trusted_hosts(&state).await;

    // Immediately poll newly added CDNs so they become available within seconds
    if !added.is_empty() {
        let s = state.clone();
        let urls_to_probe = added.clone();
        tokio::spawn(async move {
            let mut handles = Vec::with_capacity(urls_to_probe.len());
            for url in &urls_to_probe {
                let client = s.http_client.clone();
                let url = url.clone();
                handles.push(tokio::spawn(check_cdn_health(client, url)));
            }
            for handle in handles {
                let Ok((url, ok, load, error_code, ip)) = handle.await else {
                    continue;
                };
                if ok {
                    lmdb_set_cdn(
                        &s,
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
            let mut cache = s.best_cdn.write().await;
            cache.url = None;
            cache.updated = Instant::now() - Duration::from_secs(9999);
        });
    }

    Json(json!({"added": added})).into_response()
}

// ============================================================
// LINK HANDLING  (shared by /dl and /watch)
// ============================================================

#[derive(Clone, Copy)]
enum LinkKind {
    Dl,
    Watch,
}

impl LinkKind {
    fn path(self) -> &'static str {
        match self {
            LinkKind::Dl => "dl",
            LinkKind::Watch => "watch",
        }
    }
}

/// Build a redirect Response to a (relative or absolute) location.
fn redirect_to(state: &AppState, location: &str) -> Response {
    match axum::http::Response::builder()
        .status(state.config.redirect_code)
        .header(header::LOCATION, location)
        .body(Body::empty())
    {
        Ok(r) => r.into_response(),
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "invalid redirect URL"})),
        )
            .into_response(),
    }
}

/// Redirect the client to the best CDN's /dl endpoint.
async fn serve_dl(state: &AppState, hash: &str, filename: &str) -> Response {
    match get_best_cdn(state).await {
        Some(cdn) => redirect_to(state, &format!("{}/dl/{}/{}", cdn, hash, filename)),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "No CDN online"})),
        )
            .into_response(),
    }
}

/// Stream the best CDN's /watch endpoint back to the client (rewriting HTML).
async fn serve_watch(state: &AppState, hash: &str, filename: &str, headers: HeaderMap) -> Response {
    match get_best_cdn(state).await {
        Some(cdn) => {
            let upstream_url = format!("{}/watch/{}/{}", cdn, hash, filename);
            match stream_upstream(&state.http_client, &upstream_url, headers, hash, filename).await {
                Ok(resp) => resp,
                Err(status) => (status, Json(json!({"error": "upstream error"}))).into_response(),
            }
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "No CDN online"})),
        )
            .into_response(),
    }
}

/// Shared request pipeline for both /dl and /watch.
async fn handle_link(
    state: AppState,
    addr: SocketAddr,
    kind: LinkKind,
    hash: String,
    mut filename: String,
    headers: HeaderMap,
) -> Response {
    let ip = addr.ip().to_string();

    // 0. Ad callback: the arolinks destination is /<kind>/<hash>/<token>/<filename>,
    //    where <token> is an HMAC signature only this server can produce. A valid,
    //    unexpired token proves the user really went through the ad flow, so we
    //    record the watch time and redirect to the real link (which then serves
    //    directly, since the freshly-set ad_watch_time is < 2 days old). A
    //    token-shaped but invalid/expired segment is stripped so the request
    //    re-gates (shows a fresh ad) instead of leaking it into the CDN path.
    if let Some(slash) = filename.find('/') {
        let seg = filename[..slash].to_string();
        if looks_like_ad_token(&seg) {
            let rest = filename[slash + 1..].to_string();
            if verify_ad_token(&state.config.ad_secret, kind, &hash, &rest, &seg) {
                update_ad_watch_time(&state, &hash).await;
                return redirect_to(&state, &format!("/{}/{}/{}", kind.path(), hash, rest));
            }
            filename = rest;
        }
    }

    // 1. Special hash → forced ad flow (unchanged).
    if let Some(stype) = state.special_hashes.get(&hash).map(|v| v.clone()) {
        return handle_special_redirect(&state, &stype).await;
    }

    // 2. Referer blocking (unchanged).
    if referer_blocked(&state, &headers, &ip).await {
        return handle_special_redirect(&state, "one_ad").await;
    }

    // 3. Per-user ad gate: show an ad if this file's owner hasn't watched one in
    //    the last 2 days (or has no recorded ad_watch_time). Only meaningful when
    //    arolinks is configured.
    if state.config.arolinks_api.is_some() && should_show_ads(&state, &hash).await {
        if let Some(resp) = ad_redirect(&state, &headers, kind, &hash, &filename).await {
            return resp;
        }
        // Ad could not be built (no Host / shorten failed) → serve directly.
    }

    // 4. Rate limit (unchanged).
    if record_ip(&state, &ip, &hash) > state.config.max_requests_per_ip {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "IP limit exceeded"})),
        )
            .into_response();
    }

    // 5. Serve the content.
    match kind {
        LinkKind::Dl => serve_dl(&state, &hash, &filename).await,
        LinkKind::Watch => serve_watch(&state, &hash, &filename, headers).await,
    }
}

async fn dl(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(HashFilePath { hash, filename }): Path<HashFilePath>,
    headers: HeaderMap,
) -> Response {
    handle_link(state, addr, LinkKind::Dl, hash, filename, headers).await
}

async fn watch(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(HashFilePath { hash, filename }): Path<HashFilePath>,
    headers: HeaderMap,
) -> Response {
    handle_link(state, addr, LinkKind::Watch, hash, filename, headers).await
}

// ============================================================
// AD-TOKEN PURCHASE FLOW  (/ad-tokens/<user_id>/<rand>[/<token>])
// ============================================================

/// Human-readable duration like "1 day 4 hours" or "8 hours 5 min".
fn human_duration(secs: f64) -> String {
    let secs = secs.max(0.0) as u64;
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!(
            "{} day{} {} hour{}",
            days,
            if days == 1 { "" } else { "s" },
            hours,
            if hours == 1 { "" } else { "s" }
        )
    } else if hours > 0 {
        format!(
            "{} hour{} {} min",
            hours,
            if hours == 1 { "" } else { "s" },
            mins
        )
    } else {
        format!("{} min", mins)
    }
}

/// Render a simple dark-themed message page.
fn message_page(emoji: &str, title: &str, message: &str, accent: &str) -> Response {
    let html = format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>{title}</title><style>*{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}}.card{{background:#1a1f2e;border:1px solid #2d3748;border-radius:16px;padding:40px 32px;max-width:440px;text-align:center;box-shadow:0 10px 40px rgba(0,0,0,.4)}}.emoji{{font-size:3rem;margin-bottom:16px}}h1{{font-size:1.4rem;color:{accent};margin-bottom:12px}}p{{color:#a0aec0;font-size:1rem;line-height:1.6}}</style></head><body><div class="card"><div class="emoji">{emoji}</div><h1>{title}</h1><p>{message}</p></div></body></html>"#
    );
    Html(html).into_response()
}

fn ad_token_active_page(remaining: f64) -> Response {
    message_page(
        "\u{2705}",
        "You're already covered",
        &format!(
            "You already have an active ad-free token. No ads will be shown for about {}.",
            human_duration(remaining)
        ),
        "#68d391",
    )
}

fn ad_token_incremented_page(remaining: f64) -> Response {
    message_page(
        "\u{1F389}",
        "Ad-free time extended",
        &format!(
            "Your ad-free token was extended by 12 hours. You now have about {} of ad-free access.",
            human_duration(remaining)
        ),
        "#63b3ed",
    )
}

fn ad_token_unavailable_page() -> Response {
    message_page(
        "\u{1F6E0}",
        "Temporarily unavailable",
        "The ad-token service is not available right now. Please try again later.",
        "#f6ad55",
    )
}

fn ad_token_invalid_page() -> Response {
    message_page(
        "\u{26A0}",
        "Invalid link",
        "This ad-token link is malformed.",
        "#fc8181",
    )
}

/// Send the user through an arolinks ad whose destination is the signed callback
/// that grants the tokens. Falls back to the callback directly if arolinks is
/// unavailable, so the flow still completes.
async fn show_purchase_ad(state: &AppState, headers: &HeaderMap, user_id: i64, rand: &str) -> Response {
    let exp = now_unix() + AD_TOKEN_TTL_SECS;
    let token = sign_purchase_token(&state.config.ad_secret, user_id, exp);
    let callback_path = format!("/ad-tokens/{}/{}/{}", user_id, rand, token);

    if let Some(api) = state.config.arolinks_api.as_ref() {
        if let Some(base) = public_base_url(headers) {
            let callback_abs = format!("{}{}", base, callback_path);
            if let Some(short) = arolinks_shorten(
                &state.http_client,
                api,
                &state.config.arolinks_endpoint,
                &callback_abs,
            )
            .await
            {
                return axum::response::Redirect::to(&short).into_response();
            }
        }
    }
    redirect_to(state, &callback_path)
}

/// GET /ad-tokens/:user_id/:rand — entry point users click to pre-watch an ad.
async fn ad_tokens_entry(
    State(state): State<AppState>,
    Path((user_id_str, rand)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let Ok(user_id) = user_id_str.parse::<i64>() else {
        return ad_token_invalid_page();
    };
    let now = now_unix_f64();
    match user_ad_watch_time_by_id(&state, user_id).await {
        // Banked more than a day ahead already → no ad, just inform the user.
        Some(Some(awt)) if awt - now > ONE_DAY_SECS => ad_token_active_page(awt - now),
        // Eligible (awt in the past, within a day, missing, or user not found) → show ad.
        Some(_) => show_purchase_ad(&state, &headers, user_id, &rand).await,
        None => ad_token_unavailable_page(),
    }
}

/// GET /ad-tokens/:user_id/:rand/:token — arolinks callback after the ad.
async fn ad_tokens_callback(
    State(state): State<AppState>,
    Path((user_id_str, rand, token)): Path<(String, String, String)>,
) -> Response {
    let Ok(user_id) = user_id_str.parse::<i64>() else {
        return ad_token_invalid_page();
    };
    // Only accept unexpired tokens this server signed for this user.
    if !verify_purchase_token(&state.config.ad_secret, user_id, &token) {
        // Stale / tampered → restart the flow so a fresh ad is watched.
        return redirect_to(&state, &format!("/ad-tokens/{}/{}", user_id, rand));
    }
    let now = now_unix_f64();
    match user_ad_watch_time_by_id(&state, user_id).await {
        // Re-check the cap so a replayed callback can't push beyond ~1 day ahead.
        Some(Some(awt)) if awt - now > ONE_DAY_SECS => ad_token_active_page(awt - now),
        Some(existing) => {
            // Extend from whichever is later: the stored ad_watch_time or now. This
            // guarantees each ad adds usable time even if awt was in the past, so the
            // token can never get "stuck" behind the current time.
            let base = existing.unwrap_or(now).max(now);
            let new_awt = base + TWELVE_HOURS_SECS;
            set_ad_watch_time(&state, user_id, new_awt).await;
            ad_token_incremented_page(new_awt - now)
        }
        None => ad_token_unavailable_page(),
    }
}

async fn stats(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(e) = check_admin(&headers, &state.config) {
        return e;
    }
    let cdns = lmdb_list_cdns(&state).await;
    let cdn_list: Vec<Value> = cdns
        .iter()
        .map(|(url, meta)| {
            json!({
                "url": url,
                "load": meta.load,
                "last_ok": meta.last_ok,
                "fail_count": format!("{}/{}", meta.fail_count, state.config.fail_threshold),
                "updated_at": meta.updated_at,
                "error_code": meta.error_code,
                "ip": meta.ip,
            })
        })
        .collect();

    let trusted: Vec<String> = {
        let mut v: Vec<_> = state.trusted_hosts.read().await.iter().cloned().collect();
        v.sort();
        v
    };
    let best = get_best_cdn(&state).await;

    Json(json!({
        "cdns": cdn_list,
        "trusted_hosts": trusted,
        "best_cdn": best,
    }))
    .into_response()
}

// ============================================================
// RELOAD SPECIAL HASHES  (admin-only, triggered by external backend)
// ============================================================

async fn reload_special(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Err(e) = check_admin(&headers, &state.config) {
        return e;
    }
    load_special_hashes(&state).await;
    Json(json!({
        "reloaded": true,
        "count": state.special_hashes.len()
    })).into_response()
}

// ============================================================
// MAIN
// ============================================================

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
    if config.tg_redirect.is_empty() {
        anyhow::bail!("REDIRECT_TO env var is required but not set");
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
            .max_dbs(1)
            .open("cdn.lmdb")?
    });

    // create_database is idempotent: opens existing DB or creates new one.
    let lmdb_db: CdnDb = {
        let mut wtxn = env.write_txn()?;
        let db = env.create_database(&mut wtxn, Some("cdns"))?;
        wtxn.commit()?;
        db
    };

    // ── HTTP client (no global timeout – set per-request) ──────
    let http_client = reqwest::Client::builder()
        .user_agent("loadbalancer-rs/1.0")
        .build()?;

    // MongoDB for special hashes, CDN persistence, and per-user ad gating – MONGO_URL triggers all
    let (mongo_col, mongo_cdn_col, mongo_users_col): (
        Option<mongodb::Collection<mongodb::bson::Document>>,
        Option<mongodb::Collection<mongodb::bson::Document>>,
        Option<mongodb::Collection<mongodb::bson::Document>>,
    ) = if let Ok(mongo_url) = std::env::var("MONGO_URL") {
        let db_name = std::env::var("MONGO_DB_NAME")
            .map_err(|_| anyhow::anyhow!("MONGO_DB_NAME env var is required when MONGO_URL is set"))?;
        let col_name = std::env::var("MONGO_DB_COLLECTION_NAME")
            .map_err(|_| anyhow::anyhow!("MONGO_DB_COLLECTION_NAME env var is required when MONGO_URL is set"))?;
        let users_col_name = std::env::var("MONGO_USERS_COLLECTION_NAME")
            .unwrap_or_else(|_| "users".to_string());
        let mongo_client = mongodb::Client::with_uri_str(&mongo_url).await?;
        let db = mongo_client.database(&db_name);
        let special_col = db.collection::<mongodb::bson::Document>(&col_name);
        let cdn_col = db.collection::<mongodb::bson::Document>("cdn_registry");
        let users_col = db.collection::<mongodb::bson::Document>(&users_col_name);
        tracing::info!("Connected to MongoDB ({}.{}) for special hashes / file records", db_name, col_name);
        tracing::info!("Using MongoDB cdn_registry collection for CDN persistence");
        tracing::info!("Using MongoDB '{}' collection for per-user ad gating", users_col_name);
        (Some(special_col), Some(cdn_col), Some(users_col))
    } else {
        tracing::warn!("MONGO_URL not set – special hashes, CDN persistence, and ad gating disabled");
        (None, None, None)
    };

    // ── Build shared state ─────────────────────────────────────
    let state = AppState {
        lmdb_env: env,
        lmdb_db,
        mongo_col,
        mongo_cdn_col,
        mongo_users_col,
        special_hashes: Arc::new(DashMap::new()),
        best_cdn: Arc::new(RwLock::new(BestCdnCache::default())),
        rate_limiter: Arc::new(DashMap::new()),
        trusted_hosts: Arc::new(RwLock::new(HashSet::from([
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
        ]))),
        config,
        http_client,
    };

    // ── Load persisted CDNs from MongoDB cdn_registry ──────────
    if let Some(ref cdn_col) = state.mongo_cdn_col {
        match cdn_col.find(None, None).await {
            Ok(mut cursor) => {
                let mut loaded = 0usize;
                loop {
                    match cursor.advance().await {
                        Ok(true) => {
                            if let Ok(doc) = cursor.deserialize_current() {
                                if let Ok(url) = doc.get_str("_id").map(|s| s.to_string()) {
                                    if url.starts_with("http") && lmdb_get_cdn(&state, url.clone()).await.is_none() {
                                        lmdb_set_cdn(
                                            &state,
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
                }
                tracing::info!("Loaded {} CDN(s) from MongoDB cdn_registry", loaded);
            }
            Err(e) => tracing::error!("MongoDB error loading cdn_registry: {}", e),
        }
    }

    // ── Seed CDNs from LB_CDN_URLS env var ────────────────────
    if let Ok(env_cdns) = std::env::var("LB_CDN_URLS") {
        for raw in env_cdns.split(',') {
            let u = raw.trim().trim_end_matches('/').to_string();
            if u.starts_with("http") && lmdb_get_cdn(&state, u.clone()).await.is_none() {
                lmdb_set_cdn(
                    &state,
                    u.clone(),
                    CdnMeta {
                        load: 99999,
                        last_ok: 0,
                        fail_count: 0,
                        ..Default::default()
                    },
                )
                .await;
                mongo_add_cdn(&state, &u).await;
            }
        }
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
        let s = state.clone();
        tokio::spawn(poller_task(s));
        tracing::info!("CDN poller started");
    } else {
        tracing::warn!("CDN poller disabled (IS_LEADER=0)");
    }

    // ── Router ─────────────────────────────────────────────────
    let app = Router::new()
        .route("/health", get(health))
        .route("/nitai", get(nitai))
        .route("/add_cdn", post(add_cdn))
        .route("/reload_special", post(reload_special))
        .route("/dl/:hash/*filename", get(dl))
        .route("/watch/:hash/*filename", get(watch))
        .route("/ad-tokens/:user_id/:rand", get(ad_tokens_entry))
        .route("/ad-tokens/:user_id/:rand/:token", get(ad_tokens_callback))
        .route("/stats", get(stats))
        .with_state(state);

    axum::serve(
        listener,
        // ConnectInfo extractor requires this wrapper
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
