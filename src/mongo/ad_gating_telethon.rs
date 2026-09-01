//! Per-user ad gating for telethon-plgb links (payload decode → users/user_files).

use mongodb::bson::doc;

use crate::constants::{ACCOUNT_AGE_MIN_SECS, AD_INTERVAL_SECS, MIN_LINKS_FOR_ADS};
use crate::mongo::ad_gating::set_ad_watch_time;
use crate::mongo::bson_utils::{bson_datetime_to_f64, bson_to_f64, bson_to_i64};
use crate::state::{AppState, CdnPool};
use crate::time_utils::now_unix_f64;

/// Structurally decode a telethon-plgb dl/wt `payload` segment: base64url of
/// `struct.pack(">QQB", user_id, file_id, cluster)`. This does NOT verify the
/// accompanying HMAC signature (the LB doesn't hold telethon-plgb's own
/// Config.SECRET) — it's only used to read `user_id` for ad-gating, which is
/// not security-critical: the CDN itself re-verifies the signature before ever
/// serving the file, so a tampered payload only risks dodging/triggering an ad,
/// never unauthorized file access.
pub fn decode_telethon_payload(payload_b64: &str) -> Option<(i64, i64, u8)> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    if bytes.len() < 16 {
        return None;
    }
    let user_id = i64::from_be_bytes(bytes[0..8].try_into().ok()?);
    let file_id = i64::from_be_bytes(bytes[8..16].try_into().ok()?);
    let cluster = bytes.get(16).copied().unwrap_or(0);
    Some((user_id, file_id, cluster))
}

/// True if the telethon-plgb user has generated at least `min` files, summed
/// across their `uf_clusters` shard(s) (mirrors telethon-plgb's own
/// `total_user_files()`). Empty `uf_clusters` means cluster 0, same as
/// telethon-plgb; out-of-range cluster indices are clamped to 0 too.
pub async fn telethon_user_has_min_files(state: &AppState, user_id: i64, min: u64, uf_clusters: &[i64]) -> bool {
    let cols = &state.mongo_user_files_cols_telethon;
    if cols.is_empty() {
        return false;
    }
    let cluster_indices: Vec<usize> = if uf_clusters.is_empty() {
        vec![0]
    } else {
        uf_clusters
            .iter()
            .map(|&c| if c < 0 || c as usize >= cols.len() { 0 } else { c as usize })
            .collect()
    };

    let mut total: i64 = 0;
    for idx in cluster_indices {
        let Some(col) = cols.get(idx) else { continue };
        let remaining = min as i64 - total;
        if remaining <= 0 {
            return true;
        }
        let pipeline = vec![
            doc! { "$match": { "user_id": user_id } },
            doc! { "$limit": remaining },
            doc! { "$count": "n" },
        ];
        match col.aggregate(pipeline, None).await {
            Ok(mut cursor) => {
                if let Ok(true) = cursor.advance().await {
                    if let Ok(d) = cursor.deserialize_current() {
                        total += bson_to_i64(d.get("n")).unwrap_or(0);
                    }
                }
            }
            Err(e) => tracing::warn!("telethon user_files count error (cluster {}): {}", idx, e),
        }
    }
    total >= min as i64
}

/// Decide whether the telethon-plgb user embedded in `payload` should be shown
/// an ad. Mirrors plgb's `should_show_ads` gate-for-gate (Plus-plan bypass,
/// 30-day account age, 30+ links, then the ad_watch_time timer) against
/// telethon-plgb's own schema instead. Anything unresolvable → no ads
/// (loop-safe, same fail-open direction as plgb).
pub async fn telethon_should_show_ads(state: &AppState, payload_b64: &str) -> bool {
    let Some(users) = state.mongo_users_col_telethon.as_ref() else {
        return false;
    };
    let Some(uid) = decode_telethon_payload(payload_b64).map(|(user_id, _, _)| user_id) else {
        return false;
    };

    let user_doc = match users.find_one(doc! { "_id": uid }, None).await {
        Ok(Some(doc)) => doc,
        Ok(None) => return false,
        Err(e) => {
            tracing::warn!("telethon users lookup error for id {}: {}", uid, e);
            return false;
        }
    };

    // Paid ("Plus") users are never shown ads. Field is lowercase "plan" here
    // (plgb's equivalent field is "Plan").
    if matches!(user_doc.get_str("plan"), Ok(p) if p.eq_ignore_ascii_case("plus")) {
        return false;
    }

    let now = now_unix_f64();

    // Established-user gate 1: account at least 30 days old (join_date is a
    // real BSON DateTime here, unlike plgb's numeric join_date).
    match bson_datetime_to_f64(user_doc.get("join_date")) {
        Some(joined) if now - joined >= ACCOUNT_AGE_MIN_SECS => {}
        _ => return false,
    }

    // Established-user gate 2: at least 30 generated links, across uf_clusters.
    let uf_clusters: Vec<i64> = user_doc
        .get_array("uf_clusters")
        .map(|arr| arr.iter().filter_map(|b| bson_to_i64(Some(b))).collect())
        .unwrap_or_default();
    if !telethon_user_has_min_files(state, uid, MIN_LINKS_FOR_ADS, &uf_clusters).await {
        return false;
    }

    match bson_to_f64(user_doc.get("ad_watch_time")) {
        Some(t) => (now - t) > AD_INTERVAL_SECS,
        None => true,
    }
}

/// Record that the telethon-plgb user embedded in `payload` just watched an ad.
pub async fn telethon_update_ad_watch_time(state: &AppState, payload_b64: &str) {
    let Some(uid) = decode_telethon_payload(payload_b64).map(|(user_id, _, _)| user_id) else {
        return;
    };
    set_ad_watch_time(state, CdnPool::Telethon, uid, now_unix_f64()).await;
}
