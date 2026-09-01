# loadbalancer

An async HTTP load balancer / reverse proxy written in Rust ([axum](https://github.com/tokio-rs/axum)), fronting two independent Telegram-file-streaming backends:

- **plgb** ([WebStreamer](plgb/)) — `/dl` and `/watch` links
- **telethon-plgb** ([tgfs](telethon-plgb/)) — `/t/dl` and `/t/wt` links

Each backend is treated as an independent "CDN pool": its own health-checked CDN registry, its own best-CDN selection, and (optionally) its own ad-monetization gating. The two pools share nothing except the process and the admin dashboard.

Both Python projects live in this repo only as reference implementations for the schemas/behaviour this load balancer talks to — they are git-ignored and not deployed by this project.

## Features

- **Load-balanced CDN routing** — picks the CDN with the lowest reported load (±1 tie-break, random), deduplicated by resolved IP so multi-hostname CDNs on the same box aren't double-counted.
- **Background health checks** — polls every registered CDN on a timer, auto-purges CDNs that fail health checks `fail_threshold` times in a row, and persists the registry in MongoDB so it survives restarts across instances.
- **Streaming reverse proxy for `/watch`** — buffers and rewrites the HTML watch page (video `src` injection) from the chosen plgb CDN; everything else (downloads, telethon links) is a plain redirect.
- **Ad monetization (optional)** — per-user gating via Arolinks: "established" users (30+ day old account, 30+ generated files) are shown a friendly interstitial + shortened ad link every 36h; special-cased hashes get forced `zero_ad`/`one_ad`/`two_ad` flows; users can also pre-watch ads via `/ad-tokens` to bank ad-free time (+12h/ad, capped ~1 day ahead). All ad-callback links are HMAC-signed and expire after 1 hour.
- **Referer blocking & per-IP rate limiting** (plgb only).
- **Admin dashboard** at `/nitai` — live CDN status/load table for both pools, admin-key gated.
- **Per-pool master switches** — each pool's routes, poller and ad monetization can be independently disabled via env vars.

## Project structure

```
src/
  main.rs              composition root: config validation, state wiring, router, serve
  config.rs            env-driven Config
  constants.rs          ad-gating / token-TTL constants
  state.rs              AppState, CdnPool, CdnMeta, best-CDN cache
  link_kind.rs           shared /dl vs /watch discriminant
  time_utils.rs          now_unix / now_unix_f64
  lmdb_store.rs          LMDB CDN-registry CRUD (embedded, per-instance)
  cdn_selection.rs       best-CDN pick (load ±1, IP dedup, cached)
  rate_limiter.rs        per-IP sliding window
  trusted_hosts.rs       CDN host whitelist + referer blocking (plgb only)
  admin_auth.rs          x-admin-key check
  health_check.rs        CDN health probe
  poller.rs              background health-check loop, one per pool
  proxy.rs               /watch streaming reverse-proxy + HTML rewrite
  http_utils.rs          shared redirect-response helper
  mongo/                 MongoDB-backed special hashes, CDN persistence, ad gating
  ads/                   HMAC tokens, Arolinks calls, interstitial/message pages
  routes/                axum handlers, one file per route group
```

## Getting started

Requires Rust (see `Cargo.toml` for the edition) and, optionally, a MongoDB instance for CDN persistence / ad monetization.

```bash
cp .env.example .env   # create your own — see Configuration below
cargo run
```

The server binds `0.0.0.0:$PORT` (default `8000`) immediately on startup — before LMDB/MongoDB/pollers finish initializing — so health checks pass during slow cold starts.

### Docker

```bash
docker build -t loadbalancer .
docker run --rm -p 8000:8000 --env-file .env loadbalancer
```

## Configuration

All configuration is via environment variables (loaded from `.env` if present).

### Core (required)

| Variable | Description |
|---|---|
| `LB_ADMIN_KEY` | Required always. Value expected in the `x-admin-key` header for `/add_cdn*`, `/stats`, `/reload_special`. |
| `REDIRECT_TO` | Required only if the plgb pool is enabled (default). Telegram bot deep-link used as the final destination of special-hash / no-CDN-available flows. |

### Core (optional)

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8000` | HTTP listen port. |
| `LB_AD_SECRET` | falls back to `LB_ADMIN_KEY` | HMAC secret for signing ad-callback / purchase tokens. Set separately from the admin key in production. |
| `LB_POLL_INTERVAL` | `30` | Seconds between CDN health-check rounds (also the best-CDN cache TTL). `fail_threshold` = `ceil(300 / LB_POLL_INTERVAL)`. |
| `LB_MAX_REQUESTS_PER_IP` | `100` | Per-IP-per-hash request cap within `LB_TTL_SECONDS`. |
| `LB_TTL_SECONDS` | `18000` (5h) | Sliding window for the rate limiter. |
| `LB_REDIRECT_CODE` | `307` | HTTP status used for CDN redirects. |
| `LB_REFERER_WHITELIST` | *(empty)* | Comma-separated list of allowed referer hostnames (suffix-matched). CDN hostnames and loopback are always trusted. plgb only. |
| `AROLINKS_API_TOKEN` | *(unset)* | Enables ad monetization. Without it, ad flows fall back to a direct redirect. |
| `IS_LEADER` | `1` | Set to `0` to disable this instance's CDN pollers (e.g. secondary replicas). Not needed on Koyeb's free tier (single instance). |

### Per-pool switches

| Variable | Default | Effect when off |
|---|---|---|
| `LB_ENABLE_PLGB` | on | Removes `/add_cdn`, `/dl/*`, `/watch/*`, skips the plgb poller and CDN loading entirely. |
| `LB_ENABLE_TELETHON` | on | Removes `/add_cdn_telethon`, `/t/dl/*`, `/t/wt/*`, `/t/ad-tokens/*`, skips the telethon poller and CDN loading entirely. |
| `LB_SHOW_ADS_PLGB` | on | Skips the per-user ad gate on `/dl` and `/watch`; `/ad-tokens` shows an "ads are off" page. |
| `LB_SHOW_ADS_TELETHON` | on | Same, for `/t/dl` and `/t/wt`. |

Any of these accept `0`/`false`/`no`/`off` (case-insensitive) to disable; anything else, or unset, means on.

### CDN seeding

| Variable | Description |
|---|---|
| `LB_CDN_URLS` | Comma-separated plgb CDN base URLs to register on startup (in addition to whatever MongoDB has persisted). |
| `LB_CDN_URLS_TELETHON` | Same, for the telethon-plgb pool. |

CDNs can also be registered live via `POST /add_cdn` / `POST /add_cdn_telethon` (see below).

### MongoDB — plgb + LB bookkeeping

Unset `MONGO_URL` disables special hashes, CDN persistence (falls back to in-memory-only, per-instance) and plgb ad gating.

| Variable | Default | Description |
|---|---|---|
| `MONGO_URL` | — | Connection string. Setting this enables the block below. |
| `MONGO_DB_NAME` | — | Required if `MONGO_URL` is set. |
| `MONGO_DB_COLLECTION_NAME_PLGB` | — | Required if `MONGO_URL` is set. plgb's "file" collection — also holds `special_type` and each file's owner `user_id`. |
| `MONGO_USERS_COLLECTION_NAME_PLGB` | `users` | Collection holding `id`, `Plan`, `join_date`, and the LB-managed `ad_watch_time`. |

### MongoDB — telethon-plgb ad gating (optional, independent deployment)

Unset `LB_MONGO_TELETHON_URI` disables telethon-plgb ad gating (pure load balancing still works).

| Variable | Default | Description |
|---|---|---|
| `LB_MONGO_TELETHON_URI` | — | telethon-plgb's own primary MongoDB URI (same value as its `MONGODB_URI`). |
| `LB_MONGO_TELETHON_DBNAME` | `TGFS` | Database name (matches telethon-plgb's own default). |
| `LB_MONGO_TELETHON_INDEX_URI`, `LB_MONGO_TELETHON_INDEX_URI1`, `LB_MONGO_TELETHON_INDEX_URI2`, ... | — | Optional sharded `user_files` connections — copy telethon-plgb's own `MONGODB_INDEX_URI[N]` values verbatim. Falls back to a single shard on the primary connection if unset. |

## API routes

Always registered:

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness probe (`ok`). |
| GET | `/nitai` | Admin dashboard (pass `?key=<LB_ADMIN_KEY>`). |
| GET | `/stats` | Admin-only JSON snapshot of both pools' CDN registries. Requires `x-admin-key`. |
| POST | `/reload_special` | Admin-only: re-sync special hashes from MongoDB. Requires `x-admin-key`. |
| GET | `/ad-tokens/:user_id/:rand` | plgb "pre-watch an ad" entry point. |
| GET | `/ad-tokens/:user_id/:rand/:token` | plgb ad-watch callback. |

Registered when `LB_ENABLE_PLGB` (default):

| Method | Path | Description |
|---|---|---|
| POST | `/add_cdn` | Admin-only: register plgb CDN URL(s). Body `{"urls": ["https://..."]}`. Requires `x-admin-key`. |
| GET | `/dl/:hash/*filename` | Download link — redirects to the best plgb CDN (after ad/rate-limit/referer gating). |
| GET | `/watch/:hash/*filename` | Streaming watch link — proxied + HTML-rewritten from the best plgb CDN. |

Registered when `LB_ENABLE_TELETHON` (default):

| Method | Path | Description |
|---|---|---|
| POST | `/add_cdn_telethon` | Admin-only: register telethon-plgb CDN URL(s). Same body/auth as `/add_cdn`. |
| GET | `/t/dl/:payload/*rest` | Download link — redirects to the best telethon-plgb CDN. |
| GET | `/t/wt/:payload/*rest` | Inline-watch link — redirects to the best telethon-plgb CDN. |
| GET | `/t/ad-tokens/:user_id/:rand` | telethon-plgb "pre-watch an ad" entry point. |
| GET | `/t/ad-tokens/:user_id/:rand/:token` | telethon-plgb ad-watch callback. |

## Deploying on Koyeb (free tier)

This repo's `Dockerfile` is a two-stage build (compiles with `cargo build --release`, then ships a slim `debian:bookworm-slim` runtime image) — point Koyeb at this repo/Dockerfile directly.

Notes specific to the free tier:

- The free tier runs a **single instance** with **ephemeral storage** — the embedded LMDB registry (`cdn.lmdb/`) does not persist across redeploys/restarts. Configure `MONGO_URL` so the CDN registry (and special hashes / ad gating, if used) survive restarts: on boot the LB reloads any Mongo-persisted CDNs into LMDB before re-polling them.
- Leave `IS_LEADER` unset (defaults to on) — it exists for disabling the poller on secondary replicas, which the free tier doesn't have.
- Koyeb sets `PORT` automatically; the app already binds to it (defaulting to `8000` if unset).
- Set the Koyeb health-check path to `/health`.
- Set `LB_ADMIN_KEY` (and ideally a separate `LB_AD_SECRET`) as encrypted/secret env vars, not plain ones.
