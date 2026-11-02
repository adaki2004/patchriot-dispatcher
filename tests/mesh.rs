use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use patchriot_dispatcher::{AppState, relay_router};
use tower::ServiceExt;

fn app() -> axum::Router {
    // The gateway must reject these requests without contacting a database.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://fixture:fixture@127.0.0.1:1/unused")
        .unwrap();
    relay_router(
        AppState::new(
            pool,
            "fixture-internal-service-key-32-bytes".into(),
            "mesh-test".into(),
        )
        .unwrap(),
    )
}

#[tokio::test]
async fn relay_gateway_has_no_internal_routes_even_with_internal_credentials() {
    for path in [
        "/internal/devices",
        "/internal/pairing-info",
        "/internal/reviews",
        "/internal/pairings/claim",
        "/internal/sources",
        "/internal/pentests",
        "/internal/site-checks",
    ] {
        for method in ["GET", "POST"] {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .header(
                    "authorization",
                    "Bearer fixture-internal-service-key-32-bytes",
                )
                .header("x-internal-key", "fixture-internal-service-key-32-bytes")
                .header("Tailscale-User-Login", "admin@example.com")
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                app().oneshot(request).await.unwrap().status(),
                StatusCode::NOT_FOUND,
                "{method} {path}"
            );
        }
    }
}

#[tokio::test]
async fn gateway_health_is_distinct_and_pairing_still_requires_a_signed_body() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let health: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(health["service"], "patchriot-relay-gateway");
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/pairings/start")
                .header("content-type", "application/json")
                .header("Tailscale-User-Login", "admin@example.com")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}
