//! Liveness probe used by Koyeb (and anyone else) to check the process is up.

pub async fn health() -> &'static str {
    "ok"
}
