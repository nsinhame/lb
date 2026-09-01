//! CDN health-check probe (used by both the poller and the add_cdn immediate-probe path).

use std::time::Duration;

use reqwest::Client;
use serde_json::Value;

use crate::state::CdnPool;

/// Resolve the first IP address for a CDN URL (best-effort, returns empty string on failure).
pub async fn resolve_cdn_ip(url: &str) -> String {
    let Ok(parsed) = url::Url::parse(url) else { return String::new() };
    let Some(host) = parsed.host_str() else { return String::new() };
    let port = parsed.port_or_known_default().unwrap_or(80);
    let Ok(mut addrs) = tokio::net::lookup_host(format!("{}:{}", host, port)).await else {
        return String::new();
    };
    addrs.next().map(|a| a.ip().to_string()).unwrap_or_default()
}

/// Returns (url, ok, load, error_code, ip). `pool` picks the health-check path
/// (/status vs /) and the load-map JSON key ("loads" vs "load").
pub async fn check_cdn_health(client: Client, url: String, pool: CdnPool) -> (String, bool, u64, String, String) {
    let ip = resolve_cdn_ip(&url).await;
    let result = client
        .get(format!("{}{}", url, pool.health_path()))
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
                        .get(pool.load_key())
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
