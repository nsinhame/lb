//! HMAC-signed token helpers for ad-callbacks (/dl, /watch, /t/dl, /t/wt) and
//! the /ad-tokens purchase-flow callback.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::link_kind::LinkKind;
use crate::time_utils::now_unix;

type HmacSha256 = Hmac<Sha256>;

/// Low-level: hex-encoded HMAC-SHA256 of `message` under `secret`.
fn hmac_hex(secret: &str, message: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any size");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Low-level: constant-time check that `sig_hex` is a valid HMAC of `message`.
fn hmac_verify(secret: &str, message: &str, sig_hex: &str) -> bool {
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(message.as_bytes());
    mac.verify_slice(&sig_bytes).is_ok()
}

/// Split a `<exp>-<sig>` token, rejecting it if the expiry has already passed.
fn parse_signed_token(token: &str) -> Option<(u64, &str)> {
    let (exp_str, sig_hex) = token.split_once('-')?;
    let exp = exp_str.parse::<u64>().ok()?;
    if now_unix() > exp {
        return None; // expired
    }
    Some((exp, sig_hex))
}

/// Canonical string the /dl and /watch ad-callback signature is computed over.
/// Binding kind, hash, filename and expiry means a token is valid only for that link.
fn ad_token_canonical(kind: LinkKind, hash: &str, filename: &str, exp: u64) -> String {
    format!("{}:{}:{}:{}", kind.path(), hash, filename, exp)
}

/// Produce a tamper-proof /dl|/watch callback token `<exp>-<hex hmac-sha256>`.
pub fn sign_ad_token(secret: &str, kind: LinkKind, hash: &str, filename: &str, exp: u64) -> String {
    format!(
        "{}-{}",
        exp,
        hmac_hex(secret, &ad_token_canonical(kind, hash, filename, exp))
    )
}

/// Cheap structural check: does this path segment look like an ad token
/// (`<digits>-<64 hex chars>`)? Real filenames won't match this shape.
pub fn looks_like_ad_token(seg: &str) -> bool {
    match seg.split_once('-') {
        Some((exp, sig)) => {
            !exp.is_empty()
                && exp.bytes().all(|b| b.is_ascii_digit())
                && sig.len() == 64
                && sig.bytes().all(|b| b.is_ascii_hexdigit())
        }
        None => false,
    }
}

/// Verify a /dl|/watch callback token (signature match + not expired).
pub fn verify_ad_token(secret: &str, kind: LinkKind, hash: &str, filename: &str, token: &str) -> bool {
    match parse_signed_token(token) {
        Some((exp, sig_hex)) => {
            hmac_verify(secret, &ad_token_canonical(kind, hash, filename, exp), sig_hex)
        }
        None => false,
    }
}

/// Canonical string for the /ad-tokens purchase callback (binds pool + user id
/// so a token issued for one pool can't be replayed against the other).
fn purchase_canonical(pool_tag: &str, user_id: i64, exp: u64) -> String {
    format!("ad-tokens:{}:{}:{}", pool_tag, user_id, exp)
}

/// Produce a tamper-proof /ad-tokens callback token bound to `pool_tag`+`user_id`.
pub fn sign_purchase_token(secret: &str, pool_tag: &str, user_id: i64, exp: u64) -> String {
    format!("{}-{}", exp, hmac_hex(secret, &purchase_canonical(pool_tag, user_id, exp)))
}

/// Verify an /ad-tokens callback token (signature match + not expired).
pub fn verify_purchase_token(secret: &str, pool_tag: &str, user_id: i64, token: &str) -> bool {
    match parse_signed_token(token) {
        Some((exp, sig_hex)) => hmac_verify(secret, &purchase_canonical(pool_tag, user_id, exp), sig_hex),
        None => false,
    }
}

/// Canonical string for the telethon /t/dl|/t/wt ad-callback signature: binds
/// path kind + payload + sig + expiry, so it's valid only for that exact link.
fn telethon_ad_token_canonical(path: &str, payload: &str, sig: &str, exp: u64) -> String {
    format!("t-{}:{}:{}:{}", path, payload, sig, exp)
}

/// Produce a tamper-proof telethon /t/dl|/t/wt callback token.
pub fn sign_telethon_ad_token(secret: &str, path: &str, payload: &str, sig: &str, exp: u64) -> String {
    format!(
        "{}-{}",
        exp,
        hmac_hex(secret, &telethon_ad_token_canonical(path, payload, sig, exp))
    )
}

/// Verify a telethon /t/dl|/t/wt callback token (signature match + not expired).
pub fn verify_telethon_ad_token(secret: &str, path: &str, payload: &str, sig: &str, token: &str) -> bool {
    match parse_signed_token(token) {
        Some((exp, sig_hex)) => {
            hmac_verify(secret, &telethon_ad_token_canonical(path, payload, sig, exp), sig_hex)
        }
        None => false,
    }
}
