//! Async HTTP load balancer – Rust port of loadbalancer.py
//!
//! Stack:
//!   axum 0.7  – HTTP server
//!   heed 0.20 – embedded LMDB for CDN registry
//!   redis     – special-hash store
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
    extract::{ConnectInfo, OriginalUri, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use dotenvy::dotenv;
use heed::{Database, Env, EnvOpenOptions};
use rand::seq::SliceRandom;
use fred::prelude::*;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::RwLock;
use tracing::debug;

// ============================================================
// CONFIG
// ============================================================

struct Config {
    arolinks_api: Option<String>,
    arolinks_endpoint: String,
    admin_key: String,
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
            .unwrap_or(5);

        // Same formula as Python: math.ceil((5 * 60) / POLL_INTERVAL)
        let fail_threshold = (((5 * 60) as f64) / poll_interval as f64).ceil() as u64;

        Config {
            arolinks_api: std::env::var("AROLINKS_API_TOKEN").ok(),
            arolinks_endpoint: "https://arolinks.com/api".to_string(),
            admin_key: std::env::var("LB_ADMIN_KEY").unwrap_or_default(),
            tg_redirect: std::env::var("REDIRECT_TO")
                .unwrap_or_else(|_| "https://t.me/ppsl24_bot".to_string()),
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
            best_cdn_ttl: Duration::from_secs(4),
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
    /// None when REDIS_URL is not set
    redis_mgr: Option<RedisClient>,
    special_hashes: Arc<RwLock<HashSet<String>>>,
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
// REDIS – SPECIAL HASHES
// ============================================================

async fn load_special_hashes(state: &AppState) {
    let Some(client) = state.redis_mgr.clone() else {
        *state.special_hashes.write().await = HashSet::new();
        return;
    };
    match client.smembers::<HashSet<String>, _>("special_hashes").await {
        Ok(set) => *state.special_hashes.write().await = set,
        Err(e) => debug!("Redis error loading special hashes: {}", e),
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

    // Lowest load among online CDNs
    let min_load = cdns
        .iter()
        .filter(|(_, m)| m.last_ok == 1)
        .map(|(_, m)| m.load)
        .min()?; // None when no CDN is online

    // All CDNs within ±1 load unit of the minimum
    let candidates: Vec<String> = cdns
        .iter()
        .filter(|(_, m)| m.last_ok == 1 && m.load.abs_diff(min_load) <= 1)
        .map(|(u, _)| u.clone())
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

/// Returns `host/path?query` – the scheme-less clicked URL sent to Arolinks.
fn get_clicked_url(headers: &HeaderMap, uri: &str) -> String {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    format!("{}{}", host, uri)
}

async fn arolinks_shorten(
    client: &Client,
    api: &str,
    endpoint: &str,
    raw_url: &str,
) -> Option<String> {
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

async fn redirect_via_ads_or_bot(state: &AppState, headers: &HeaderMap, uri: &str) -> Response {
    let raw_url = get_clicked_url(headers, uri);
    if let Some(api) = &state.config.arolinks_api {
        if let Some(short) = arolinks_shorten(
            &state.http_client,
            api,
            &state.config.arolinks_endpoint,
            &raw_url,
        )
        .await
        {
            return axum::response::Redirect::to(&short).into_response();
        }
    }
    axum::response::Redirect::to(&state.config.tg_redirect).into_response()
}

// ============================================================
// HTML REWRITING  (fix missing filename in /dl/<hash> URLs)
// ============================================================

fn fix_video_src(html: &str, hash: &str, filename: &str) -> String {
    let escaped = regex::escape(hash);
    // Match /dl/<hash> NOT followed by /  (idempotent)
    let pattern = format!(r"/dl/{}(?!/)", escaped);
    match Regex::new(&pattern) {
        Ok(re) => re
            .replace_all(html, format!("/dl/{}/{}", hash, filename).as_str())
            .into_owned(),
        Err(_) => html.to_string(),
    }
}

// ============================================================
// CDN HEALTH CHECK
// ============================================================

async fn check_cdn_health(client: Client, url: String) -> (String, bool, u64) {
    let result = client
        .get(format!("{}/status", url))
        .timeout(Duration::from_secs(3))
        .send()
        .await;

    match result {
        Ok(resp) => match resp.json::<Value>().await {
            Ok(js) => {
                let total: u64 = js
                    .get("loads")
                    .and_then(|l| l.as_object())
                    .map(|m| m.values().filter_map(|v| v.as_u64()).sum())
                    .unwrap_or(99999);
                (url, true, total)
            }
            Err(_) => (url, false, 99999),
        },
        Err(_) => (url, false, 99999),
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
            let Ok((url, ok, load)) = handle.await else {
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
                        ts: 0,
                    },
                )
                .await;
            } else {
                let fail_count = prev_fail + 1;
                if fail_count >= state.config.fail_threshold {
                    debug!("Purging dead CDN: {}", url);
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
                            ts: 0,
                        },
                    )
                    .await;
                }
            }
        }

        rebuild_trusted_hosts(&state).await;
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

    if content_type.contains("text/html") {
        // Buffer the HTML, rewrite video src, then send
        let body_bytes = resp
            .bytes()
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        let html = String::from_utf8_lossy(&body_bytes);
        let fixed = fix_video_src(&html, hash, filename);

        let mut builder = axum::http::Response::builder().status(upstream_status);
        for (k, v) in &upstream_headers {
            builder = builder.header(k, v);
        }
        Ok(builder
            .body(Body::from(fixed))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
    } else {
        // Stream bytes directly to the client without buffering
        // reqwest::Error: Into<BoxError> via std blanket impl, so no .map_err needed
        let body = Body::from_stream(resp.bytes_stream());

        let mut builder = axum::http::Response::builder().status(upstream_status);
        for (k, v) in &upstream_headers {
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
                    added.push(url);
                }
            }
        }
    }
    rebuild_trusted_hosts(&state).await;
    Json(json!({"added": added})).into_response()
}

async fn add_special(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Json(body): axum::extract::Json<Value>,
) -> Response {
    if let Err(e) = check_admin(&headers, &state.config) {
        return e;
    }
    let hashes: Vec<String> = body
        .get("hashes")
        .and_then(|h| h.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    if let Some(client) = state.redis_mgr.clone() {
        for h in &hashes {
            let _: Result<i64, _> = client.sadd("special_hashes", h.as_str()).await;
        }
    }
    load_special_hashes(&state).await;
    Json(json!({"added": hashes})).into_response()
}

async fn dl(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(HashFilePath { hash, filename }): Path<HashFilePath>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let ip = addr.ip().to_string();
    let is_special = state.special_hashes.read().await.contains(&hash);

    if referer_blocked(&state, &headers, &ip).await || is_special {
        return redirect_via_ads_or_bot(&state, &headers, &uri.to_string()).await;
    }

    if record_ip(&state, &ip, &hash) > state.config.max_requests_per_ip {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "IP limit exceeded"})),
        )
            .into_response();
    }

    match get_best_cdn(&state).await {
        Some(cdn) => {
            let target = format!("{}/dl/{}/{}", cdn, hash, filename);
            // Build redirect with configurable status code (307 default)
            axum::http::Response::builder()
                .status(state.config.redirect_code)
                .header(header::LOCATION, &target)
                .body(Body::empty())
                .unwrap()
                .into_response()
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "No CDN online"})),
        )
            .into_response(),
    }
}

async fn watch(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(HashFilePath { hash, filename }): Path<HashFilePath>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let ip = addr.ip().to_string();
    let is_special = state.special_hashes.read().await.contains(&hash);

    if referer_blocked(&state, &headers, &ip).await || is_special {
        return redirect_via_ads_or_bot(&state, &headers, &uri.to_string()).await;
    }

    if record_ip(&state, &ip, &hash) > state.config.max_requests_per_ip {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "IP limit exceeded"})),
        )
            .into_response();
    }

    match get_best_cdn(&state).await {
        Some(cdn) => {
            let upstream_url = format!("{}/watch/{}/{}", cdn, hash, filename);
            match stream_upstream(&state.http_client, &upstream_url, headers, &hash, &filename)
                .await
            {
                Ok(resp) => resp,
                Err(status) => {
                    (status, Json(json!({"error": "upstream error"}))).into_response()
                }
            }
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "No CDN online"})),
        )
            .into_response(),
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
            })
        })
        .collect();

    let trusted: Vec<String> = {
        let mut v: Vec<_> = state.trusted_hosts.read().await.iter().cloned().collect();
        v.sort();
        v
    };
    let best = get_best_cdn(&state).await;
    let specials: Vec<String> = state.special_hashes.read().await.iter().cloned().collect();

    Json(json!({
        "cdns": cdn_list,
        "trusted_hosts": trusted,
        "best_cdn": best,
        "special_hashes": specials,
    }))
    .into_response()
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

    // ── Redis ──────────────────────────────────────────────────
    let redis_mgr = if let Ok(url) = std::env::var("REDIS_URL") {
        // fred v9: use Config (renamed from RedisConfig) + Builder
        let config = fred::types::config::Config::from_url(&url)?;
        let client = Builder::from_config(config).build()?;
        // init() drives the connection; TLS is auto-detected from rediss:// URL
        client.init().await?;
        Some(client)
    } else {
        None
    };

    // ── HTTP client (no global timeout – set per-request) ──────
    let http_client = reqwest::Client::builder()
        .user_agent("loadbalancer-rs/1.0")
        .build()?;

    // ── Build shared state ─────────────────────────────────────
    let state = AppState {
        lmdb_env: env,
        lmdb_db,
        redis_mgr,
        special_hashes: Arc::new(RwLock::new(HashSet::new())),
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

    // ── Seed CDNs from LB_CDN_URLS env var ────────────────────
    if let Ok(env_cdns) = std::env::var("LB_CDN_URLS") {
        for raw in env_cdns.split(',') {
            let u = raw.trim().trim_end_matches('/').to_string();
            if u.starts_with("http") && lmdb_get_cdn(&state, u.clone()).await.is_none() {
                lmdb_set_cdn(
                    &state,
                    u,
                    CdnMeta {
                        load: 99999,
                        last_ok: 0,
                        fail_count: 0,
                        ..Default::default()
                    },
                )
                .await;
            }
        }
    }

    rebuild_trusted_hosts(&state).await;
    load_special_hashes(&state).await;

    // ── Background: refresh special hashes every 60 s ─────────
    {
        let s = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                load_special_hashes(&s).await;
            }
        });
    }

    // ── Background: CDN poller (leader instance only) ─────────
    // On Koyeb, only the instance whose ID ends in "0" is the leader.
    // Locally (no KOYEB_INSTANCE_ID set) the poller does NOT start;
    // set IS_LEADER=1 in your .env to force it on.
    let is_leader = std::env::var("KOYEB_INSTANCE_ID")
        .map(|id| id.ends_with('0'))
        .unwrap_or_else(|_| {
            std::env::var("IS_LEADER")
                .map(|v| v == "1")
                .unwrap_or(false)
        });

    if is_leader {
        let s = state.clone();
        tokio::spawn(poller_task(s));
        tracing::info!("CDN poller started (leader instance)");
    }

    // ── Router ─────────────────────────────────────────────────
    let app = Router::new()
        .route("/health", get(health))
        .route("/add_cdn", post(add_cdn))
        .route("/add_special", post(add_special))
        .route("/dl/:hash/*filename", get(dl))
        .route("/watch/:hash/*filename", get(watch))
        .route("/stats", get(stats))
        .with_state(state);

    // PORT env var (Koyeb / Render / Fly.io inject this automatically)
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8000);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        // ConnectInfo extractor requires this wrapper
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
