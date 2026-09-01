//! Per-user ad gating for plgb links (file collection → users collection).

use mongodb::bson::doc;

use crate::constants::{ACCOUNT_AGE_MIN_SECS, AD_INTERVAL_SECS, MIN_LINKS_FOR_ADS};
use crate::mongo::bson_utils::{bson_to_f64, bson_to_i64};
use crate::state::{AppState, CdnPool};
use crate::time_utils::now_unix_f64;

/// Look up a file's owner `user_id` in the file collection, keyed by the URL hash
/// (which is the document `_id` — an ObjectId hex, or a plain string fallback).
pub async fn file_user_id(state: &AppState, hash: &str) -> Option<i64> {
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
pub async fn user_has_min_files(state: &AppState, user_id: i64, min: u64) -> bool {
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
///   * ad_watch_time older than AD_INTERVAL_SECS (36 hours) → show ads
///   * ad_watch_time field missing on an existing user doc → show ads
/// Anything unresolvable (Mongo off, user/user_id/join_date missing, too new,
/// too few links, or a query error) → serve directly (loop-safe: guarantees the
/// post-ad callback can't re-trigger ads).
pub async fn should_show_ads(state: &AppState, hash: &str) -> bool {
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

    // Paid ("Plus") users are never shown ads.
    if matches!(user_doc.get_str("Plan"), Ok(p) if p.eq_ignore_ascii_case("plus")) {
        return false;
    }

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
pub async fn update_ad_watch_time(state: &AppState, hash: &str) {
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

/// Read a user's ad_watch_time by their pool-specific id field. Returns:
///   Some(Some(t)) = user found with ad_watch_time,
///   Some(None)    = user found without it, or user not found,
///   None          = users collection unavailable / query failed.
pub async fn user_ad_watch_time_by_id(state: &AppState, pool: CdnPool, user_id: i64) -> Option<Option<f64>> {
    let users = pool.users_col(state)?;
    let mut filter = mongodb::bson::Document::new();
    filter.insert(pool.user_id_field(), user_id);
    match users.find_one(filter, None).await {
        Ok(Some(user_doc)) => Some(bson_to_f64(user_doc.get("ad_watch_time"))),
        Ok(None) => Some(None),
        Err(e) => {
            tracing::warn!("users lookup error for id {}: {}", user_id, e);
            None
        }
    }
}

/// Set a user's ad_watch_time to an absolute value (upserts the user doc).
pub async fn set_ad_watch_time(state: &AppState, pool: CdnPool, user_id: i64, value: f64) -> bool {
    let Some(users) = pool.users_col(state) else {
        return false;
    };
    let mut filter = mongodb::bson::Document::new();
    filter.insert(pool.user_id_field(), user_id);
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
