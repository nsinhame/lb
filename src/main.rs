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
use rand::seq::SliceRandom;
use mongodb::bson::doc;
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
    /// MongoDB collection for special hashes (None if MONGO_URL not set)
    mongo_col: Option<mongodb::Collection<mongodb::bson::Document>>,
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
  const totalLoad = online.reduce((s, c) => s + (c.load < 99999 ? c.load : 0), 0);

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
      const lc = loadColor(c.load);
      const bw = loadBarWidth(c.load);
      const loadDisp = c.load >= 99999 ? '∞' : c.load;
      return `<tr>
        <td title="${c.url}" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${host}</td>
        <td><span class="badge ${c.last_ok === 1 ? 'online' : 'offline'}">${c.last_ok === 1 ? 'Online' : 'Offline'}</span></td>
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
                let Ok((url, ok, load)) = handle.await else {
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
                            ts: 0,
                        },
                    )
                    .await;
                    tracing::info!("CDN {} is online (load={})", url, load);
                } else {
                    tracing::warn!("CDN {} did not respond to initial health check", url);
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

async fn dl(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(HashFilePath { hash, filename }): Path<HashFilePath>,
    headers: HeaderMap,
) -> Response {
    let ip = addr.ip().to_string();

    // Special hash check: redirect before any other logic
    if let Some(stype) = state.special_hashes.get(&hash).map(|v| v.clone()) {
        return handle_special_redirect(&state, &stype).await;
    }

    if referer_blocked(&state, &headers, &ip).await {
        return handle_special_redirect(&state, "one_ad").await;
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
            match axum::http::Response::builder()
                .status(state.config.redirect_code)
                .header(header::LOCATION, &target)
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
    headers: HeaderMap,
) -> Response {
    let ip = addr.ip().to_string();

    // Special hash check: redirect before any other logic
    if let Some(stype) = state.special_hashes.get(&hash).map(|v| v.clone()) {
        return handle_special_redirect(&state, &stype).await;
    }

    if referer_blocked(&state, &headers, &ip).await {
        return handle_special_redirect(&state, "one_ad").await;
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

    Json(json!({
        "cdns": cdn_list,
        "trusted_hosts": trusted,
        "best_cdn": best,
    }))
    .into_response()
}

// ============================================================
// ADD SPECIAL HASH  (MongoDB only)
// ============================================================

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
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    let special_type = body
        .get("special_type")
        .and_then(|v| v.as_str())
        .unwrap_or("zero_ad")
        .to_string();

    if let Some(col) = &state.mongo_col {
        for h in &hashes {
            let filter = doc! { "_id": h };
            let update = doc! { "$set": { "_id": h, "special_type": &special_type } };
            let opts = mongodb::options::UpdateOptions::builder().upsert(true).build();
            if let Err(e) = col.update_one(filter, update, opts).await {
                debug!("MongoDB upsert error for hash {}: {}", h, e);
            }
        }
    }

    // Insert directly into in-memory cache – no full reload needed
    for h in &hashes {
        state.special_hashes.insert(h.clone(), special_type.clone());
    }

    Json(json!({"added": hashes, "special_type": special_type})).into_response()
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

    // MongoDB for special hashes – all three env vars are required when MONGO_URL is set
    let mongo_col: Option<mongodb::Collection<mongodb::bson::Document>> =
        if let Ok(mongo_url) = std::env::var("MONGO_URL") {
            let db_name = std::env::var("MONGO_DB_NAME")
                .map_err(|_| anyhow::anyhow!("MONGO_DB_NAME env var is required when MONGO_URL is set"))?;
            let col_name = std::env::var("MONGO_DB_COLLECTION_NAME")
                .map_err(|_| anyhow::anyhow!("MONGO_DB_COLLECTION_NAME env var is required when MONGO_URL is set"))?;
            let mongo_client = mongodb::Client::with_uri_str(&mongo_url).await?;
            let col = mongo_client
                .database(&db_name)
                .collection::<mongodb::bson::Document>(&col_name);
            tracing::info!("Connected to MongoDB ({}.{}) for special hashes", db_name, col_name);
            Some(col)
        } else {
            tracing::warn!("MONGO_URL not set – special hashes disabled");
            None
        };

    // ── Build shared state ─────────────────────────────────────
    let state = AppState {
        lmdb_env: env,
        lmdb_db,
        mongo_col,
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
        .route("/add_special", post(add_special))
        .route("/dl/:hash/*filename", get(dl))
        .route("/watch/:hash/*filename", get(watch))
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
