//! Device admission and liveness. Customer work is not enabled by pairing alone.

mod credentials;
mod devices;
pub use credentials::run_cleanup;
pub mod ownership;
mod reviews;
pub mod screening;
mod sources;
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
    internal_hash: Option<Arc<[u8; 32]>>,
    pub audience: Arc<str>,
    agent_attempt_seconds: u64,
    credential_vault: Option<Arc<credentials::Vault>>,
    owned_test_origins: Arc<[String]>,
}

impl AppState {
    pub fn new(pool: PgPool, internal_key: String, audience: String) -> Result<Self, &'static str> {
        if internal_key.len() < 32
            || internal_key.len() > 256
            || internal_key.chars().any(char::is_whitespace)
        {
            return Err("internal key must be 32..256 non-whitespace bytes");
        }
        let mut state = Self::relay_only(pool, audience)?;
        state.internal_hash = Some(Arc::new(Sha256::digest(internal_key.as_bytes()).into()));
        Ok(state)
    }

    /// Signed device routes need no core service key. Even if this state is
    /// accidentally passed to the full router, it cannot authorize internal calls.
    pub fn relay_only(pool: PgPool, audience: String) -> Result<Self, &'static str> {
        if audience.is_empty() || audience.len() > 200 || audience.chars().any(char::is_control) {
            return Err("invalid deployment audience");
        }
        Ok(Self {
            pool,
            internal_hash: None,
            audience: audience.into(),
            agent_attempt_seconds: patchriot_protocol::DEFAULT_AGENT_ATTEMPT_SECONDS,
            credential_vault: None,
            owned_test_origins: Arc::from([]),
        })
    }

    pub fn with_agent_attempt_seconds(mut self, seconds: u64) -> Result<Self, &'static str> {
        if !(patchriot_protocol::DEFAULT_AGENT_ATTEMPT_SECONDS
            ..=patchriot_protocol::MAX_AGENT_ATTEMPT_SECONDS)
            .contains(&seconds)
        {
            return Err("agent attempt limit must be 600..3600 seconds");
        }
        self.agent_attempt_seconds = seconds;
        Ok(self)
    }

    pub fn with_credential_key(mut self, key: Option<String>) -> Result<Self, &'static str> {
        self.credential_vault = key
            .map(|key| credentials::Vault::from_hex(&key).map(Arc::new))
            .transpose()?;
        Ok(self)
    }

    /// Off by default. Staff must still grant each exact request explicitly.
    /// Removing this configuration disables new grants; revoke existing grants
    /// through the normal scope decision endpoint to stop their active work.
    pub fn with_owned_test_origins(mut self, origins: Vec<String>) -> Result<Self, &'static str> {
        if origins.len() > 16 {
            return Err("too many owned test origins");
        }
        for (index, origin) in origins.iter().enumerate() {
            let parsed = patchriot_protocol::pentests::public_url(origin)?;
            if parsed.origin().ascii_serialization() != *origin || origins[..index].contains(origin)
            {
                return Err("owned test origins must be distinct, exact HTTPS origins");
            }
        }
        self.owned_test_origins = origins.into();
        Ok(self)
    }

    fn agent_review_seconds(&self) -> u64 {
        patchriot_protocol::agent_review_seconds(self.agent_attempt_seconds)
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

fn device_routes() -> Router<AppState> {
    Router::new()
        .route("/v1/fleet", get(devices::fleet))
        .route("/v1/pairings/start", post(devices::start))
        .route("/v1/pairings/status", post(devices::pairing_status))
        .route("/v1/devices/{id}/heartbeat", post(devices::heartbeat))
        .route(
            "/v1/devices/{id}/work/source-evidence",
            post(reviews::sources::evidence),
        )
        .route(
            "/v1/devices/{id}/work/pentest-evidence",
            post(reviews::pentests::evidence),
        )
        .route("/v1/devices/{id}/work/poll", post(reviews::poll))
        .route("/v1/devices/{id}/work/renew", post(reviews::renew))
        .route(
            "/v1/devices/{id}/work/evidence",
            post(reviews::websites::evidence),
        )
        .route(
            "/v1/devices/{id}/work/complete",
            post(reviews::complete).layer(DefaultBodyLimit::max(
                patchriot_protocol::pentests::MAX_RESULT_BYTES + 8192,
            )),
        )
}

fn finish_router(router: Router<AppState>, state: AppState) -> Router {
    router
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ))
        .with_state(state)
}

/// Existing internal/local listener. Keep this on loopback when using the mesh gateway.
pub fn router(state: AppState) -> Router {
    let router = device_routes()
        .route(
            "/health",
            get(|| async {
                Json(serde_json::json!({"status": "ok", "version": env!("CARGO_PKG_VERSION")}))
            }),
        )
        .route("/internal/pairings/claim", post(devices::claim))
        .route("/internal/pairing-info", get(devices::pairing_info))
        .route("/internal/agents", get(devices::agents))
        .route("/internal/devices", get(devices::list))
        .route("/internal/devices/{id}/decision", post(devices::decision))
        .route(
            "/internal/reviews",
            get(reviews::list).post(reviews::create),
        )
        .route("/internal/reviews/{id}", get(reviews::get))
        .route(
            "/internal/reviews/{id}/download",
            post(reviews::retention::download),
        )
        .route("/internal/reviews/{id}/cancel", post(reviews::cancel))
        .route("/internal/reviews/{id}/fund", post(reviews::funding::fund))
        .route(
            "/internal/site-checks",
            get(websites::list).post(websites::create),
        )
        .route("/internal/site-checks/{id}", get(websites::detail))
        .route(
            "/internal/site-checks/{id}/compare/{baseline_id}",
            get(websites::compare),
        )
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
            "/internal/site-checks/{id}/admit-review",
            post(reviews::funding::admit),
        )
        .route(
            "/internal/site-checks/{id}/evidence",
            get(websites::artifact),
        )
        .route(
            "/internal/sources",
            get(sources::list)
                .post(sources::create)
                .layer(DefaultBodyLimit::max(
                    patchriot_protocol::sources::MAX_SOURCE_BODY_BYTES,
                )),
        )
        .route(
            "/internal/pentests",
            get(reviews::pentests::list).post(reviews::pentests::create),
        )
        .route("/internal/pentest-tools", get(reviews::pentests::tools))
        .route(
            "/internal/pentests/{id}/credentials",
            post(reviews::pentests::set_credentials),
        )
        .route(
            "/internal/pentests/{id}/authorize-owned-test",
            post(reviews::pentests::authorize_owned_test),
        )
        .route(
            "/internal/pentests/{id}/decision",
            post(reviews::pentests::decide),
        )
        .route("/internal/pentests/{id}/ownership", get(ownership::get))
        .route(
            "/internal/pentests/{id}/ownership/refresh",
            post(ownership::refresh),
        )
        .route(
            "/internal/pentests/{id}/review-plan",
            get(reviews::pentests::plan),
        )
        .route(
            "/internal/pentests/{id}/review",
            post(reviews::pentests::start),
        )
        .route(
            "/internal/pentests/{id}/admit-review",
            post(reviews::pentests::admit),
        )
        .route("/internal/sources/{id}", get(sources::detail))
        .route("/internal/sources/{id}/decision", post(sources::decide))
        .route("/internal/sources/{id}/delete", post(sources::delete))
        .route("/internal/sources/{id}/evidence", get(sources::artifact))
        .route(
            "/internal/sources/{id}/review-plan",
            get(reviews::sources::plan),
        )
        .route(
            "/internal/sources/{id}/review",
            post(reviews::sources::create),
        )
        .route(
            "/internal/sources/{id}/admit-review",
            post(reviews::sources::admit),
        );
    finish_router(router, state)
}

/// Agent-facing listener for Tailscale Serve. Internal routes do not exist here,
/// even if a client supplies the internal service key or forged proxy headers.
/// Tailscale limits network access; device signatures and approval still apply.
pub fn relay_router(state: AppState) -> Router {
    finish_router(device_routes().route("/health", get(|| async {
        Json(serde_json::json!({"status": "ok", "service": "patchriot-relay-gateway", "version": env!("CARGO_PKG_VERSION")}))
    })), state)
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
    let expected = state
        .internal_hash
        .as_deref()
        .ok_or_else(ApiError::denied)?;
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::denied)?;
    let hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if !bool::from(expected.ct_eq(&hash)) {
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
