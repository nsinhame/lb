//! Tunable constants shared across ad-gating, token-signing, and the
//! /ad-tokens pre-watch flow.

/// A user is shown ads again once their last ad is older than this window.
/// Hard-coded to 36 hours (in seconds) per product requirement.
pub const AD_INTERVAL_SECS: f64 = 36.0 * 60.0 * 60.0;

/// Ads are only shown to "established" users: their account must be at least
/// this old (by join_date) AND they must have generated at least
/// MIN_LINKS_FOR_ADS files. Newer / lighter users are never shown ads.
pub const ACCOUNT_AGE_MIN_SECS: f64 = 30.0 * 24.0 * 60.0 * 60.0; // 30 days
pub const MIN_LINKS_FOR_ADS: u64 = 30;

/// How long a signed ad-callback token stays valid (covers the arolinks
/// round-trip). After this it is rejected, preventing indefinite replay.
pub const AD_TOKEN_TTL_SECS: u64 = 60 * 60; // 1 hour

/// /ad-tokens "purchase" flow: users pre-watch ads to bank ad-free time.
/// Each ad grants 12h; users are blocked once they are banked > 1 day ahead
/// (so at most ~2 ads/day worth of ad-free time can be accumulated).
pub const ONE_DAY_SECS: f64 = 24.0 * 60.0 * 60.0;
pub const TWELVE_HOURS_SECS: f64 = 12.0 * 60.0 * 60.0;
