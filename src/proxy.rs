//! Streaming reverse-proxy for /watch (plgb) — buffers+rewrites HTML,
//! streams everything else through untouched.

use axum::body::Body;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use regex::Regex;
use reqwest::Client;

pub fn fix_video_src(html: &str, hash: &str, filename: &str) -> String {
    let escaped = regex::escape(hash);
    // The `regex` crate does not support lookaheads, so we use a capture group
    // instead: match /dl/<hash> followed by any non-slash character and capture
    // that character so we can put it back in the replacement.
    // This is idempotent: /dl/<hash>/<filename> won't match because the char
    // immediately after <hash> is '/', which is excluded by [^/].
    let pattern = format!(r"/dl/{}([^/])", escaped);
    match Regex::new(&pattern) {
        Ok(re) => re
            .replace_all(html, format!("/dl/{}/{}$1", hash, filename).as_str())
            .into_owned(),
        Err(_) => html.to_string(),
    }
}

pub async fn stream_upstream(
    client: &Client,
    upstream_url: &str,
    mut req_headers: HeaderMap,
    hash: &str,
    filename: &str,
) -> Result<Response, StatusCode> {
    req_headers.remove(header::HOST);
    // Remove Accept-Encoding so the CDN returns uncompressed HTML we can parse and rewrite.
    // Without this, the CDN may return gzip-encoded bytes that look like garbage to fix_video_src.
    req_headers.remove(header::ACCEPT_ENCODING);

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

    // Hop-by-hop headers must NOT be forwarded to the client.
    // Forwarding Transfer-Encoding: chunked causes double-encoding: reqwest already
    // decodes the upstream chunking, so axum/hyper applies its own chunking on top.
    // Envoy then sees a malformed body and resets the connection before sending headers.
    let is_hop_by_hop = |name: &str| {
        matches!(
            name,
            "connection"
                | "keep-alive"
                | "transfer-encoding"
                | "te"
                | "trailers"
                | "upgrade"
                | "proxy-authenticate"
                | "proxy-authorization"
        )
    };

    if content_type.contains("text/html") {
        // Buffer the HTML, rewrite video src, then send
        let body_bytes = resp.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;
        let html = String::from_utf8_lossy(&body_bytes);
        let fixed = fix_video_src(&html, hash, filename);
        let fixed_bytes = fixed.into_bytes();

        let mut builder = axum::http::Response::builder().status(upstream_status);
        for (k, v) in &upstream_headers {
            let name = k.as_str().to_lowercase();
            // Skip hop-by-hop headers AND Content-Length: the body changed after
            // fix_video_src, so the upstream length is now wrong.
            if name == "content-length" || is_hop_by_hop(&name) {
                continue;
            }
            builder = builder.header(k, v);
        }
        // Set correct Content-Length for the rewritten body.
        builder = builder.header(header::CONTENT_LENGTH, fixed_bytes.len());
        Ok(builder
            .body(Body::from(fixed_bytes))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
    } else {
        // Stream bytes directly to the client without buffering
        // reqwest::Error: Into<BoxError> via std blanket impl, so no .map_err needed
        let body = Body::from_stream(resp.bytes_stream());

        let mut builder = axum::http::Response::builder().status(upstream_status);
        for (k, v) in &upstream_headers {
            let name = k.as_str().to_lowercase();
            if is_hop_by_hop(&name) {
                continue;
            }
            builder = builder.header(k, v);
        }
        Ok(builder
            .body(body)
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
    }
}
