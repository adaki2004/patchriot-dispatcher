use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use http_body_util::BodyExt;
use patchriot_dispatcher::{AppState, router};
use patchriot_protocol::*;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower::ServiceExt;
use uuid::Uuid;

struct TestApp {
    app: Router,
    pool: PgPool,
    admin_pool: PgPool,
    schema: String,
    internal_key: String,
    owner: Uuid,
    admin: Uuid,
}

impl TestApp {
    async fn new() -> Self {
        let url = std::env::var("PATCHRIOT_TEST_DATABASE_URL")
            .expect("set PATCHRIOT_TEST_DATABASE_URL to a local test PostgreSQL database");
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("test_devices_{}", Uuid::new_v4().simple());
        // The identifier is entirely generated here from a fixed prefix and UUID
        // hex digits. No request or environment value becomes SQL text.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin_pool)
            .await
            .unwrap();
        let search = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .after_connect(move |connection, _| {
                let search = search.clone();
                Box::pin(async move {
                    sqlx::query("SELECT set_config('search_path', $1, false)")
                        .bind(search)
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let internal_key = format!("fixture-service-auth-{}", Uuid::new_v4());
        let app = router(
            AppState::new(pool.clone(), internal_key.clone(), "test-deployment".into()).unwrap(),
        );
        Self {
            app,
            pool,
            admin_pool,
            schema,
            internal_key,
            owner: Uuid::new_v4(),
            admin: Uuid::new_v4(),
        }
    }

    async fn finish(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin_pool)
        .await
        .unwrap();
        self.admin_pool.close().await;
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Value,
        actor: Option<(Uuid, bool)>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some((id, admin)) = actor {
            req = req
                .header("authorization", format!("Bearer {}", self.internal_key))
                .header("x-patchriot-account", id.to_string())
                .header("x-patchriot-role", if admin { "admin" } else { "member" });
        }
        let response = self
            .app
            .clone()
            .oneshot(
                req.body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"text": String::from_utf8_lossy(&bytes)}));
        (status, body)
    }

    async fn signed<T: Serialize>(
        &self,
        key: &DeviceKey,
        path: &str,
        body: T,
    ) -> (StatusCode, Value) {
        let request = sign(key, "test-deployment", path, Utc::now().timestamp(), body).unwrap();
        self.request("POST", path, serde_json::to_value(request).unwrap(), None)
            .await
    }

    fn introduction() -> DeviceIntroduction {
        DeviceIntroduction {
            label: "Fixture relay".into(),
            runtime: RuntimeKind::OwnedFixture,
            runtime_version: "0.0.1".into(),
            declared_model: None,
            compute_group: "shared-demo-machine".into(),
            slots: 1,
        }
    }

    async fn start(&self, key: &DeviceKey) -> PairingStarted {
        let (status, body) = self
            .signed(key, PAIRING_START_PATH, Self::introduction())
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        serde_json::from_value(body).unwrap()
    }

    async fn claim(&self, code: &str, owner: Uuid) -> (StatusCode, Value) {
        self.request("POST", "/internal/pairings/claim", json!({"user_code": code, "display_name": "Test contributor", "hosting": "own_machine", "accepts_private_work_rules": true}), Some((owner, false))).await
    }

    async fn paired(&self, key: &DeviceKey) -> Uuid {
        let pair = self.start(key).await;
        let (status, body) = self.claim(&pair.user_code, self.owner).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        serde_json::from_value::<PairingStatus>(body)
            .unwrap()
            .device_id
            .unwrap()
    }

    async fn approve(&self, id: Uuid) {
        let (status, body) = self
            .request(
                "POST",
                &format!("/internal/devices/{id}/decision"),
                json!({"action":"approve", "reason":"Owned-fixture pilot"}),
                Some((self.admin, true)),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
}

#[tokio::test]
async fn pairs_requires_separate_approval_tracks_presence_and_revokes() {
    let test = TestApp::new().await;
    let key = DeviceKey::from_bytes(&[11; 32]);
    let id = test.paired(&key).await;
    let path = format!("/v1/devices/{id}/heartbeat");
    let (_, pending) = test
        .signed(
            &key,
            &path,
            Heartbeat {
                sequence: 1,
                paused: false,
                running: 0,
            },
        )
        .await;
    assert_eq!(pending["state"], "awaiting_approval");
    let (_, fleet) = test.request("GET", "/v1/fleet", Value::Null, None).await;
    assert_eq!(fleet["online_devices"], 0);
    test.approve(id).await;
    let (_, online) = test
        .signed(
            &key,
            &path,
            Heartbeat {
                sequence: 2,
                paused: false,
                running: 0,
            },
        )
        .await;
    assert_eq!(online["state"], "online");
    let (_, fleet) = test.request("GET", "/v1/fleet", Value::Null, None).await;
    assert_eq!(fleet["online_devices"], 1);
    assert_eq!(fleet["online_operators"], 1);
    assert_eq!(fleet["online_compute_groups"], 1);
    let (_, paused) = test
        .signed(
            &key,
            &path,
            Heartbeat {
                sequence: 3,
                paused: true,
                running: 0,
            },
        )
        .await;
    assert_eq!(paused["state"], "paused");
    let (_, fleet) = test.request("GET", "/v1/fleet", Value::Null, None).await;
    assert_eq!(fleet["online_devices"], 0);
    let (status, _) = test
        .request(
            "POST",
            &format!("/internal/devices/{id}/decision"),
            json!({"action":"revoke","reason":"Owner unpaired"}),
            Some((test.owner, false)),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = test
        .signed(
            &key,
            &path,
            Heartbeat {
                sequence: 4,
                paused: false,
                running: 0,
            },
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "device_revoked");
    let (status, _) = test
        .request(
            "POST",
            &format!("/internal/devices/{id}/decision"),
            json!({"action":"approve","reason":null}),
            Some((test.admin, true)),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    test.finish().await;
}

#[tokio::test]
async fn old_or_conflicting_heartbeats_do_not_refresh_liveness() {
    let test = TestApp::new().await;
    let key = DeviceKey::from_bytes(&[12; 32]);
    let id = test.paired(&key).await;
    test.approve(id).await;
    let path = format!("/v1/devices/{id}/heartbeat");
    let heartbeat = Heartbeat {
        sequence: 1,
        paused: false,
        running: 0,
    };
    let (status, _) = test.signed(&key, &path, heartbeat.clone()).await;
    assert_eq!(status, StatusCode::OK);
    sqlx::query("UPDATE devices SET last_seen_at = now() - interval '1 minute' WHERE id = $1")
        .bind(id)
        .execute(&test.pool)
        .await
        .unwrap();
    let (_, replay) = test.signed(&key, &path, heartbeat).await;
    assert_eq!(replay["replayed"], true);
    assert_eq!(replay["state"], "offline");
    let (status, _) = test
        .signed(
            &key,
            &path,
            Heartbeat {
                sequence: 1,
                paused: true,
                running: 0,
            },
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, live) = test
        .signed(
            &key,
            &path,
            Heartbeat {
                sequence: 2,
                paused: false,
                running: 0,
            },
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(live["state"], "online");
    // Rebuilding the application must not reset counters or approval.
    let reopened = router(
        AppState::new(
            test.pool.clone(),
            test.internal_key.clone(),
            "test-deployment".into(),
        )
        .unwrap(),
    );
    let signed = sign(
        &key,
        "test-deployment",
        &path,
        Utc::now().timestamp(),
        Heartbeat {
            sequence: 1,
            paused: false,
            running: 0,
        },
    )
    .unwrap();
    let response = reopened
        .oneshot(
            Request::post(&path)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&signed).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    test.finish().await;
}

#[tokio::test]
async fn account_boundaries_and_device_signatures_are_enforced() {
    let test = TestApp::new().await;
    let key = DeviceKey::from_bytes(&[13; 32]);
    let other_key = DeviceKey::from_bytes(&[14; 32]);
    let other = Uuid::new_v4();
    let pair = test.start(&key).await;
    let (_, body) = test.claim(&pair.user_code, test.owner).await;
    let id = serde_json::from_value::<PairingStatus>(body)
        .unwrap()
        .device_id
        .unwrap();
    let (status, _) = test
        .request("GET", "/internal/devices", Value::Null, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, devices) = test
        .request(
            "GET",
            "/internal/devices",
            Value::Null,
            Some((other, false)),
        )
        .await;
    assert_eq!(devices, json!([]));
    let (status, _) = test.claim(&pair.user_code, other).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = test
        .request(
            "POST",
            &format!("/internal/devices/{id}/decision"),
            json!({"action":"approve","reason":null}),
            Some((test.owner, false)),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = test
        .request(
            "POST",
            &format!("/internal/devices/{id}/decision"),
            json!({"action":"revoke","reason":null}),
            Some((other, false)),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = test
        .signed(
            &other_key,
            PAIRING_STATUS_PATH,
            PairingStatusInput {
                pairing_id: pair.pairing_id,
            },
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = test
        .signed(
            &other_key,
            &format!("/v1/devices/{id}/heartbeat"),
            Heartbeat {
                sequence: 1,
                paused: false,
                running: 0,
            },
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let forged = Request::get("/internal/devices")
        .header("x-patchriot-account", test.admin.to_string())
        .header("x-patchriot-role", "admin")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        test.app.clone().oneshot(forged).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    test.finish().await;
}

#[tokio::test]
async fn pairing_is_idempotent_expires_and_cannot_be_claimed_twice_concurrently() {
    let test = TestApp::new().await;
    let key = DeviceKey::from_bytes(&[15; 32]);
    let pair = test.start(&key).await;
    let retry = test.start(&key).await;
    assert_eq!(pair.pairing_id, retry.pairing_id);
    assert_eq!(pair.expires_at, retry.expires_at);
    let other = Uuid::new_v4();
    let (a, b) = tokio::join!(
        test.claim(&pair.user_code, test.owner),
        test.claim(&pair.user_code, other)
    );
    assert_eq!(
        [a.0, b.0].iter().filter(|&&s| s == StatusCode::OK).count(),
        1
    );
    assert_eq!(
        [a.0, b.0]
            .iter()
            .filter(|&&s| s == StatusCode::CONFLICT)
            .count(),
        1
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM devices")
        .fetch_one(&test.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let expiring_key = DeviceKey::from_bytes(&[16; 32]);
    let expiring = test.start(&expiring_key).await;
    sqlx::query("UPDATE pairings SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(expiring.pairing_id)
        .execute(&test.pool)
        .await
        .unwrap();
    let (status, body) = test.claim(&expiring.user_code, test.owner).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "pairing_expired");
    test.finish().await;
}

#[tokio::test]
async fn anonymous_pairing_growth_and_request_size_are_bounded() {
    let test = TestApp::new().await;
    for seed in 20..40 {
        test.start(&DeviceKey::from_bytes(&[seed; 32])).await;
    }
    let (status, body) = test
        .signed(
            &DeviceKey::from_bytes(&[40; 32]),
            PAIRING_START_PATH,
            TestApp::introduction(),
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"], "pairing_capacity_reached");
    let request = Request::post(PAIRING_START_PATH)
        .header("content-type", "application/json")
        .body(Body::from("x".repeat(20_000)))
        .unwrap();
    assert_eq!(
        test.app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    test.finish().await;
}
