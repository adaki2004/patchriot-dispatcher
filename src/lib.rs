//! Device admission and liveness. Customer work is not enabled by pairing alone.

mod devices;
mod reviews;
pub mod websites;

use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::{sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tower_http::set_header::SetResponseHeaderLayer;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    internal_hash: Arc<[u8; 32]>,
    pub audience: Arc<str>,
}

impl AppState {
    pub fn new(pool: PgPool, internal_key: String, audience: String) -> Result<Self, &'static str> {
        if internal_key.len() < 32
            || internal_key.len() > 256
            || internal_key.chars().any(char::is_whitespace)
        {
            return Err("internal key must be 32..256 non-whitespace bytes");
        }
        if audience.is_empty() || audience.len() > 200 || audience.chars().any(char::is_control) {
            return Err("invalid deployment audience");
        }
        Ok(Self {
            pool,
            internal_hash: Arc::new(Sha256::digest(internal_key.as_bytes()).into()),
            audience: audience.into(),
        })
    }
}

pub async fn connect(url: &str) -> Result<PgPool, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET statement_timeout = '5s'")
                    .execute(&mut *connection)
                    .await?;
                Ok(())
            })
        })
        .connect(url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/health",
            get(|| async {
                Json(serde_json::json!({"status": "ok", "version": env!("CARGO_PKG_VERSION")}))
            }),
        )
        .route("/v1/fleet", get(devices::fleet))
        .route("/v1/pairings/start", post(devices::start))
        .route("/v1/pairings/status", post(devices::pairing_status))
        .route("/v1/devices/{id}/heartbeat", post(devices::heartbeat))
        .route("/internal/pairings/claim", post(devices::claim))
        .route("/internal/devices", get(devices::list))
        .route("/internal/devices/{id}/decision", post(devices::decision))
        .route(
            "/internal/reviews",
            get(reviews::list).post(reviews::create),
        )
        .route("/internal/reviews/{id}", get(reviews::get))
        .route("/internal/reviews/{id}/cancel", post(reviews::cancel))
        .route(
            "/internal/site-checks",
            get(websites::list).post(websites::create),
        )
        .route("/internal/site-checks/{id}", get(websites::detail))
        .route(
            "/internal/site-checks/{id}/decision",
            post(websites::decide),
        )
        .route("/internal/site-checks/{id}/cancel", post(websites::cancel))
        .route(
            "/internal/site-checks/{id}/review-plan",
            get(reviews::websites::plan),
        )
        .route(
            "/internal/site-checks/{id}/review",
            post(reviews::websites::create),
        )
        .route(
            "/internal/site-checks/{id}/evidence",
            get(websites::artifact),
        )
        .route("/v1/devices/{id}/work/poll", post(reviews::poll))
        .route("/v1/devices/{id}/work/renew", post(reviews::renew))
        .route(
            "/v1/devices/{id}/work/evidence",
            post(reviews::websites::evidence),
        )
        .route(
            "/v1/devices/{id}/work/complete",
            post(reviews::complete).layer(DefaultBodyLimit::max(64 * 1024)),
        )
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .with_state(state)
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
}

pub(crate) struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str) -> Self {
        Self { status, code }
    }
    pub fn bad(code: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code)
    }
    pub fn denied() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized")
    }
    pub fn missing() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found")
    }
    pub fn conflict(code: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, code)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorBody { error: self.code })).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(_: sqlx::Error) -> Self {
        // Never return SQL, bound customer values or connection details to callers.
        eprintln!("dispatcher database operation failed");
        Self::new(StatusCode::SERVICE_UNAVAILABLE, "database_unavailable")
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(_: serde_json::Error) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "invalid_stored_data")
    }
}

pub(crate) struct Actor {
    id: Uuid,
    admin: bool,
}

/// These headers may only be constructed by core after authenticating its session.
/// A browser forwarding the same headers without the separate service key is denied.
fn actor(headers: &HeaderMap, state: &AppState) -> Result<Actor, ApiError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::denied)?;
    let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if !bool::from(state.internal_hash.as_ref().ct_eq(&hash)) {
        return Err(ApiError::denied());
    }
    let id = headers
        .get("x-patchriot-account")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse().ok())
        .ok_or_else(ApiError::denied)?;
    let role = headers
        .get("x-patchriot-role")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(ApiError::denied)?;
    if !["member", "admin"].contains(&role) {
        return Err(ApiError::denied());
    }
    Ok(Actor {
        id,
        admin: role == "admin",
    })
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn verify<T: Serialize>(
    request: &patchriot_protocol::SignedRequest<T>,
    state: &AppState,
    path: &str,
) -> Result<(), ApiError> {
    patchriot_protocol::verify(request, &state.audience, path, now())
        .map_err(|code| ApiError::new(StatusCode::UNAUTHORIZED, code))
}
