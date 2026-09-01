//! /ad-tokens pre-watch "purchase" flow (banks ad-free time), shared by both
//! pools via `route_prefix()` ("" for plgb, "/t" for telethon).

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::Response;

use crate::ads::arolinks::{arolinks_shorten, public_base_url};
use crate::ads::pages::{
    ad_interstitial_page, ad_token_active_page, ad_token_ads_off_page, ad_token_incremented_page,
    ad_token_invalid_page, ad_token_unavailable_page,
};
use crate::ads::tokens::{sign_purchase_token, verify_purchase_token};
use crate::constants::{AD_TOKEN_TTL_SECS, ONE_DAY_SECS, TWELVE_HOURS_SECS};
use crate::http_utils::redirect_to;
use crate::mongo::ad_gating::{set_ad_watch_time, user_ad_watch_time_by_id};
use crate::state::{AppState, CdnPool};
use crate::time_utils::{now_unix, now_unix_f64};

/// Send the user through an arolinks ad whose destination is the signed callback
/// that grants the tokens. Falls back to the callback directly if arolinks is
/// unavailable, so the flow still completes.
async fn show_purchase_ad(state: &AppState, headers: &HeaderMap, pool: CdnPool, user_id: i64, rand: &str) -> Response {
    let exp = now_unix() + AD_TOKEN_TTL_SECS;
    let token = sign_purchase_token(&state.config.ad_secret, pool.tag(), user_id, exp);
    let callback_path = format!("{}/ad-tokens/{}/{}/{}", pool.route_prefix(), user_id, rand, token);

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
                return ad_interstitial_page(
                    &short,
                    "your ad-free time will be extended by 12 hours",
                );
            }
        }
    }
    redirect_to(state, &callback_path)
}

/// Shared handler for GET [/t]/ad-tokens/:user_id/:rand — entry point users
/// click to pre-watch an ad.
async fn ad_tokens_entry_generic(state: AppState, pool: CdnPool, user_id_str: String, rand: String, headers: HeaderMap) -> Response {
    let Ok(user_id) = user_id_str.parse::<i64>() else {
        return ad_token_invalid_page();
    };
    if !pool.show_ads(&state) {
        return ad_token_ads_off_page();
    }
    let now = now_unix_f64();
    match user_ad_watch_time_by_id(&state, pool, user_id).await {
        // Banked more than a day ahead already → no ad, just inform the user.
        Some(Some(awt)) if awt - now > ONE_DAY_SECS => ad_token_active_page(awt - now),
        // Eligible (awt in the past, within a day, missing, or user not found) → show ad.
        Some(_) => show_purchase_ad(&state, &headers, pool, user_id, &rand).await,
        None => ad_token_unavailable_page(),
    }
}

pub async fn ad_tokens_entry(
    State(state): State<AppState>,
    Path((user_id_str, rand)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    ad_tokens_entry_generic(state, CdnPool::Plgb, user_id_str, rand, headers).await
}

pub async fn t_ad_tokens_entry(
    State(state): State<AppState>,
    Path((user_id_str, rand)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    ad_tokens_entry_generic(state, CdnPool::Telethon, user_id_str, rand, headers).await
}

/// Shared handler for GET [/t]/ad-tokens/:user_id/:rand/:token — arolinks
/// callback after the ad.
async fn ad_tokens_callback_generic(state: AppState, pool: CdnPool, user_id_str: String, rand: String, token: String) -> Response {
    let Ok(user_id) = user_id_str.parse::<i64>() else {
        return ad_token_invalid_page();
    };
    // Only accept unexpired tokens this server signed for this user+pool.
    if !verify_purchase_token(&state.config.ad_secret, pool.tag(), user_id, &token) {
        // Stale / tampered → restart the flow so a fresh ad is watched.
        return redirect_to(&state, &format!("{}/ad-tokens/{}/{}", pool.route_prefix(), user_id, rand));
    }
    let now = now_unix_f64();
    match user_ad_watch_time_by_id(&state, pool, user_id).await {
        // Re-check the cap so a replayed callback can't push beyond ~1 day ahead.
        Some(Some(awt)) if awt - now > ONE_DAY_SECS => ad_token_active_page(awt - now),
        Some(existing) => {
            // Extend from whichever is later: the stored ad_watch_time or now. This
            // guarantees each ad adds usable time even if awt was in the past, so the
            // token can never get "stuck" behind the current time.
            let base = existing.unwrap_or(now).max(now);
            let new_awt = base + TWELVE_HOURS_SECS;
            set_ad_watch_time(&state, pool, user_id, new_awt).await;
            ad_token_incremented_page(new_awt - now)
        }
        None => ad_token_unavailable_page(),
    }
}

pub async fn ad_tokens_callback(
    State(state): State<AppState>,
    Path((user_id_str, rand, token)): Path<(String, String, String)>,
) -> Response {
    ad_tokens_callback_generic(state, CdnPool::Plgb, user_id_str, rand, token).await
}

pub async fn t_ad_tokens_callback(
    State(state): State<AppState>,
    Path((user_id_str, rand, token)): Path<(String, String, String)>,
) -> Response {
    ad_tokens_callback_generic(state, CdnPool::Telethon, user_id_str, rand, token).await
}
