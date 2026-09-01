//! In-process sliding-window rate limiter, keyed by "ip:hash".

use std::time::{Duration, Instant};

use crate::state::AppState;

pub fn record_ip(state: &AppState, ip: &str, hash: &str) -> usize {
    let key = format!("{}:{}", ip, hash);
    let ttl = Duration::from_secs(state.config.ttl_seconds);
    let now = Instant::now();
    let mut entry = state.rate_limiter.entry(key).or_default();
    entry.retain(|&t| now.duration_since(t) < ttl);
    entry.push(now);
    entry.len()
}
