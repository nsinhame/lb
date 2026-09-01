//! Special-hash forced redirect flow (zero_ad / one_ad / two_ad) — plgb only.

use axum::response::{IntoResponse, Redirect, Response};

use crate::ads::arolinks::arolinks_shorten;
use crate::state::AppState;

pub async fn handle_special_redirect(state: &AppState, special_type: &str) -> Response {
    let tg = state.config.tg_redirect.clone();

    match special_type {
        // zero_ad: no ads – go straight to the Telegram bot
        "zero_ad" => Redirect::to(&tg).into_response(),

        // one_ad: one Arolinks ad, destination is the Telegram bot
        "one_ad" => {
            if let Some(api) = &state.config.arolinks_api {
                if let Some(short) =
                    arolinks_shorten(&state.http_client, api, &state.config.arolinks_endpoint, &tg).await
                {
                    return Redirect::to(&short).into_response();
                }
            }
            Redirect::to(&tg).into_response()
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
                        return Redirect::to(&short1).into_response();
                    }
                    // Second shorten failed – degrade to one ad
                    return Redirect::to(&short2).into_response();
                }
            }
            Redirect::to(&tg).into_response()
        }

        // Unknown type – fall back to Telegram bot
        _ => Redirect::to(&tg).into_response(),
    }
}
