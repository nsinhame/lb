//! Environment-driven configuration for the load balancer.

use std::{collections::HashSet, time::Duration};

pub struct Config {
    pub arolinks_api: Option<String>,
    pub arolinks_endpoint: String,
    pub admin_key: String,
    /// Secret used to HMAC-sign ad-callback tokens (falls back to admin_key).
    pub ad_secret: String,
    /// Master switch for showing ads on plgb links (LB_SHOW_ADS_PLGB; default on).
    pub show_ads_plgb: bool,
    /// Master switch for showing ads on telethon-plgb links (LB_SHOW_ADS_TELETHON; default on).
    pub show_ads_telethon: bool,
    pub tg_redirect: String,
    /// Master switch for the plgb CDN pool/routes (LB_ENABLE_PLGB; default on).
    pub enable_plgb: bool,
    /// Master switch for the telethon-plgb CDN pool/routes (LB_ENABLE_TELETHON; default on).
    pub enable_telethon: bool,
    pub max_requests_per_ip: usize,
    pub ttl_seconds: u64,
    pub poll_interval: u64,
    pub redirect_code: u16,
    pub fail_threshold: u64,
    pub referer_whitelist: HashSet<String>,
    pub best_cdn_ttl: Duration,
}

impl Config {
    pub fn from_env() -> Self {
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

        // Unset -> ads on; "0"/"false"/"no"/"off" -> ads disabled for that pool.
        // Split per-pool (rather than one global switch) so plgb and telethon-plgb
        // monetization can be toggled independently.
        let show_ads_plgb = std::env::var("LB_SHOW_ADS_PLGB")
            .ok()
            .map(|v| !matches!(v.trim().to_lowercase().as_str(), "0" | "false" | "no" | "off"))
            .unwrap_or(true);
        let show_ads_telethon = std::env::var("LB_SHOW_ADS_TELETHON")
            .ok()
            .map(|v| !matches!(v.trim().to_lowercase().as_str(), "0" | "false" | "no" | "off"))
            .unwrap_or(true);

        // Per-pool master switches. Unset -> pool on; "0"/"false"/"no"/"off" -> that
        // pool's routes/poller/CDN loading are skipped entirely.
        let enable_plgb = std::env::var("LB_ENABLE_PLGB")
            .ok()
            .map(|v| !matches!(v.trim().to_lowercase().as_str(), "0" | "false" | "no" | "off"))
            .unwrap_or(true);
        let enable_telethon = std::env::var("LB_ENABLE_TELETHON")
            .ok()
            .map(|v| !matches!(v.trim().to_lowercase().as_str(), "0" | "false" | "no" | "off"))
            .unwrap_or(true);

        Config {
            arolinks_api: std::env::var("AROLINKS_API_TOKEN").ok(),
            arolinks_endpoint: "https://arolinks.com/api".to_string(),
            admin_key,
            ad_secret,
            show_ads_plgb,
            show_ads_telethon,
            tg_redirect: std::env::var("REDIRECT_TO").unwrap_or_default(),
            enable_plgb,
            enable_telethon,
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

/// Read an ordered list of numbered env vars sharing `prefix`: the bare
/// `prefix` (if set) comes first, then `prefix1`, `prefix2`, ... sorted
/// ascending. Mirrors telethon-plgb's own `ConfigBase.get_numbered_tokens`, so
/// the same MONGODB_INDEX_URI[N] values can be copied verbatim into
/// LB_MONGO_TELETHON_INDEX_URI[N].
pub fn numbered_env_values(prefix: &str) -> Vec<String> {
    let mut bare: Option<String> = None;
    let mut numbered: Vec<(u32, String)> = Vec::new();
    for (key, value) in std::env::vars() {
        if key == prefix {
            bare = Some(value);
        } else if let Some(suffix) = key.strip_prefix(prefix) {
            if let Ok(n) = suffix.parse::<u32>() {
                numbered.push((n, value));
            }
        }
    }
    numbered.sort_by_key(|(n, _)| *n);
    let mut result: Vec<String> = bare.into_iter().collect();
    result.extend(numbered.into_iter().map(|(_, v)| v));
    result
}
