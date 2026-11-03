use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use chrono::Utc;
use http_body_util::BodyExt;
use patchriot_dispatcher::{AppState, relay_router, router};
use patchriot_protocol::*;
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgPoolOptions};
use tower::ServiceExt;
use uuid::Uuid;

#[path = "pentests/mod.rs"]
mod live_tests;
#[path = "sites/mod.rs"]
mod sites;
#[path = "sources/mod.rs"]
mod source_reviews;
#[path = "sites/reviews.rs"]
mod website_reviews;

#[tokio::test]
async fn admitted_agent_directory_excludes_operator_details_and_unapproved_devices() {
    let test = TestApp::new().await;
    let key = DeviceKey::from_bytes(&[201; 32]);
    let id = test.online(&key).await;
    let pending_key = DeviceKey::from_bytes(&[202; 32]);
    let pending = test.paired(&pending_key).await;
    let caller = Some((Uuid::new_v4(), false));
    for path in ["/internal/agents", "/internal/pairing-info"] {
        assert_eq!(
            test.request("GET", path, Value::Null, None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    let (status, body) = test
        .request("GET", "/internal/agents", Value::Null, caller)
        .await;
    assert_eq!(status, StatusCode::OK);
    let agents = body.as_array().unwrap();
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0]["id"], id.to_string());
    assert_ne!(agents[0]["id"], pending.to_string());
    assert_eq!(agents[0]["reported_os"], "linux");
    assert_eq!(agents[0]["state"], "online");
    let mut fields: Vec<_> = agents[0]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort();
    assert_eq!(
        fields,
        [
            "declared_model",
            "id",
            "last_seen_at",
            "live_tests",
            "live_tools",
            "reported_os",
            "reports_received",
            "runtime",
            "runtime_version",
            "state"
        ]
    );
    let (_, info) = test
        .request("GET", "/internal/pairing-info", Value::Null, caller)
        .await;
    assert_eq!(info, json!({"audience":"test-deployment"}));
    sqlx::query("UPDATE devices SET approval = 'revoked' WHERE id = $1")
        .bind(id)
        .execute(&test.pool)
        .await
        .unwrap();
    let (_, after) = test
        .request("GET", "/internal/agents", Value::Null, caller)
        .await;
    assert_eq!(after, json!([]));
    test.finish().await;
}

#[tokio::test]
async fn signed_system_details_update_existing_agents_without_exposing_machine_identity() {
    let test = TestApp::new().await;
    let key = DeviceKey::from_bytes(&[203; 32]);
    let id = test.online(&key).await;
    let path = format!("/v1/devices/{id}/heartbeat");
    let system = AgentSystem {
        os_name: "Kali GNU/Linux".into(),
        os_version: Some("2026.3".into()),
        architecture: "x86_64".into(),
        relay_version: "0.0.1".into(),
    };
    let mut heartbeat = Heartbeat {
        sequence: 2,
        paused: false,
        running: 0,
        system: Some(system.clone()),
    };
    assert_eq!(
        test.signed(&key, &path, heartbeat.clone()).await.0,
        StatusCode::OK
    );
    assert_eq!(
        test.signed(&key, &path, heartbeat.clone()).await.1["replayed"],
        true
    );
    heartbeat.system.as_mut().unwrap().os_version = Some("changed".into());
    assert_eq!(
        test.signed(&key, &path, heartbeat.clone()).await.0,
        StatusCode::CONFLICT
    );
    heartbeat.sequence = 3;
    heartbeat.system.as_mut().unwrap().os_name = "invalid\nname".into();
    assert_eq!(
        test.signed(&key, &path, heartbeat.clone()).await.0,
        StatusCode::BAD_REQUEST
    );
    heartbeat.system = None; // Older relay heartbeats keep the latest known details.
    assert_eq!(test.signed(&key, &path, heartbeat).await.0, StatusCode::OK);
    let (_, list) = test
        .request(
            "GET",
            "/internal/agents",
            Value::Null,
            Some((Uuid::new_v4(), false)),
        )
        .await;
    assert_eq!(list[0]["system"], serde_json::to_value(system).unwrap());
    assert_eq!(list[0]["reports_received"], 0);
    for field in [
        "compute_group",
        "operator_id",
        "operator_name",
        "public_key",
        "label",
    ] {
        assert!(list[0].get(field).is_none());
    }
    let (_, own) = test
        .request(
            "GET",
            "/internal/devices",
            Value::Null,
            Some((test.owner, false)),
        )
        .await;
    assert_eq!(own[0]["system"], list[0]["system"]);
    test.finish().await;
}

struct TestApp {
    app: Router,
    relay: Option<Router>,
    pool: PgPool,
    admin_pool: PgPool,
    schema: String,
    internal_key: String,
    owner: Uuid,
    admin: Uuid,
}

impl TestApp {
    async fn new() -> Self {
        Self::with_budget(600).await
    }

    async fn with_budget(seconds: u64) -> Self {
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
            AppState::new(pool.clone(), internal_key.clone(), "test-deployment".into())
                .unwrap()
                .with_agent_attempt_seconds(seconds)
                .unwrap(),
        );
        Self {
            app,
            relay: None,
            pool,
            admin_pool,
            schema,
            internal_key,
            owner: Uuid::new_v4(),
            admin: Uuid::new_v4(),
        }
    }

    fn change_budget(&mut self, seconds: u64) {
        self.app = router(
            AppState::new(
                self.pool.clone(),
                self.internal_key.clone(),
                "test-deployment".into(),
            )
            .unwrap()
            .with_agent_attempt_seconds(seconds)
            .unwrap(),
        );
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
        let response = if path.starts_with("/v1/") {
            self.relay.as_ref().unwrap_or(&self.app)
        } else {
            &self.app
        }
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
            reported_os: Some("linux".into()),
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

    async fn online(&self, key: &DeviceKey) -> Uuid {
        let id = self.paired(key).await;
        self.approve(id).await;
        let response = self
            .signed(
                key,
                &format!("/v1/devices/{id}/heartbeat"),
                Heartbeat {
                    system: None,
                    sequence: 1,
                    paused: false,
                    running: 0,
                },
            )
            .await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        id
    }

    async fn review(&self, request_id: Uuid) -> ReviewView {
        let response = self
            .request(
                "POST",
                "/internal/reviews",
                json!({"request_id":request_id,"scenario":"access_control_v1"}),
                Some((self.owner, false)),
            )
            .await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        serde_json::from_value(response.1).unwrap()
    }

    async fn work(&self, key: &DeviceKey, id: Uuid, sequence: u64) -> Option<WorkAssignment> {
        let response = self
            .signed(
                key,
                &format!("/v1/devices/{id}/work/poll"),
                WorkPoll {
                    sequence,
                    website_reviews: false,
                    source_reviews: false,
                    live_tests: false,
                    live_tools: vec![],
                },
            )
            .await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        serde_json::from_value::<WorkReply>(response.1)
            .unwrap()
            .assignment
    }

    async fn complete_work(
        &self,
        key: &DeviceKey,
        id: Uuid,
        lease: Uuid,
        result: FixtureResult,
    ) -> (StatusCode, Value) {
        self.signed(
            key,
            &format!("/v1/devices/{id}/work/complete"),
            CompleteWork {
                lease_id: lease,
                result: WorkResult::Fixture(result),
            },
        )
        .await
    }

    async fn agent(&self, key: &DeviceKey, owner: Uuid) -> Uuid {
        let introduction = DeviceIntroduction {
            runtime: RuntimeKind::Hermes,
            runtime_version: "test-runtime".into(),
            declared_model: Some("test-local-model".into()),
            ..Self::introduction()
        };
        let response = self.signed(key, PAIRING_START_PATH, introduction).await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        let pair: PairingStarted = serde_json::from_value(response.1).unwrap();
        let response = self.claim(&pair.user_code, owner).await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        let id = serde_json::from_value::<PairingStatus>(response.1)
            .unwrap()
            .device_id
            .unwrap();
        self.approve(id).await;
        assert_eq!(
            self.signed(
                key,
                &format!("/v1/devices/{id}/heartbeat"),
                Heartbeat {
                    system: None,
                    sequence: 1,
                    paused: false,
                    running: 0
                }
            )
            .await
            .0,
            StatusCode::OK
        );
        id
    }

    async fn agent_review(&self) -> ReviewView {
        let response = self.request("POST", "/internal/reviews", json!({"request_id":Uuid::new_v4(), "scenario":"access_control_v1", "mode":"owned_agent"}), Some((self.owner, false))).await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        serde_json::from_value(response.1).unwrap()
    }

    async fn renew(
        &self,
        key: &DeviceKey,
        id: Uuid,
        lease_id: Uuid,
        sequence: u64,
    ) -> (StatusCode, Value) {
        self.signed(
            key,
            &format!("/v1/devices/{id}/work/renew"),
            RenewWork {
                lease_id,
                sequence,
                progress: None,
            },
        )
        .await
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
                system: None,
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
                system: None,
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
                system: None,
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
                system: None,
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
        system: None,
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
                system: None,
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
                system: None,
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
            system: None,
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
                system: None,
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

fn fixture_result() -> FixtureResult {
    FixtureResult {
        runs: [
            FixtureVersion::Original,
            FixtureVersion::Patched,
            FixtureVersion::Clean,
        ]
        .into_iter()
        .map(|version| FixtureRun {
            version,
            completed: true,
            elapsed_ms: 10,
            checks: [
                FixtureCheck {
                    name: "owner_can_read".into(),
                    expected: true,
                    actual: true,
                },
                FixtureCheck {
                    name: "another_user_can_read".into(),
                    expected: false,
                    actual: version == FixtureVersion::Original,
                },
                FixtureCheck {
                    name: "anonymous_can_read".into(),
                    expected: false,
                    actual: false,
                },
            ]
            .into(),
        })
        .collect(),
    }
}

#[tokio::test]
async fn standalone_gateway_preserves_signed_pairing_approval_and_work_delivery() {
    let mut test = TestApp::new().await;
    test.relay = Some(relay_router(
        AppState::relay_only(test.pool.clone(), "test-deployment".into()).unwrap(),
    ));
    let review = test.review(Uuid::new_v4()).await;
    let key = DeviceKey::from_bytes(&[79; 32]);
    let id = test.paired(&key).await;
    let pending = test
        .signed(
            &key,
            &format!("/v1/devices/{id}/heartbeat"),
            Heartbeat {
                system: None,
                sequence: 1,
                paused: false,
                running: 0,
            },
        )
        .await;
    assert_eq!(pending.0, StatusCode::OK);
    assert_eq!(pending.1["state"], "awaiting_approval");
    let unapproved = test
        .signed(
            &key,
            &format!("/v1/devices/{id}/work/poll"),
            WorkPoll {
                sequence: 1,
                website_reviews: false,
                source_reviews: false,
                live_tests: false,
                live_tools: vec![],
            },
        )
        .await;
    assert_eq!(unapproved.0, StatusCode::FORBIDDEN);
    test.approve(id).await;
    let heartbeat = test
        .signed(
            &key,
            &format!("/v1/devices/{id}/heartbeat"),
            Heartbeat {
                system: None,
                sequence: 2,
                paused: false,
                running: 0,
            },
        )
        .await;
    assert_eq!(heartbeat.0, StatusCode::OK, "{}", heartbeat.1);
    let wrong_key = DeviceKey::from_bytes(&[80; 32]);
    let wrong = test
        .signed(
            &wrong_key,
            &format!("/v1/devices/{id}/work/poll"),
            WorkPoll {
                sequence: 1,
                website_reviews: false,
                source_reviews: false,
                live_tests: false,
                live_tools: vec![],
            },
        )
        .await;
    assert_eq!(wrong.0, StatusCode::UNAUTHORIZED);
    let assignment = test.work(&key, id, 1).await.unwrap();
    assert_eq!(assignment.review_id, review.id);
    let (status, body) = test
        .complete_work(&key, id, assignment.lease_id, fixture_result())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["fixture_matches"], true);
    test.finish().await;
}

#[tokio::test]
async fn queued_fixture_uses_three_distinct_devices_and_preserves_requester_privacy() {
    let test = TestApp::new().await;
    let request = Uuid::new_v4();
    let review = test.review(request).await;
    assert_eq!(review.id, test.review(request).await.id);
    assert_eq!(review.steps.len(), 3);
    for seed in 51..54 {
        let key = DeviceKey::from_bytes(&[seed; 32]);
        let id = test.online(&key).await;
        let assignment = test.work(&key, id, 1).await.unwrap();
        assert_eq!(assignment.review_id, review.id);
        let (status, body) = test
            .complete_work(&key, id, assignment.lease_id, fixture_result())
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["fixture_matches"], true);
        // One device cannot fill the other review roles, even with spare capacity.
        assert!(test.work(&key, id, 2).await.is_none());
    }
    let path = format!("/internal/reviews/{}", review.id);
    let (status, body) = test
        .request("GET", &path, Value::Null, Some((test.owner, false)))
        .await;
    assert_eq!(status, StatusCode::OK);
    let view: ReviewView = serde_json::from_value(body).unwrap();
    assert_eq!(view.state, "completed");
    assert_eq!(view.mode, "owned_fixture");
    assert_eq!(
        view.evidence_source,
        "device_reported_fixture_not_independently_verified"
    );
    assert_eq!(
        view.steps
            .iter()
            .filter_map(|s| s.device_id)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
    assert_eq!(
        view.steps
            .iter()
            .filter_map(|s| s.operator_id)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        1
    );
    let unrelated = Uuid::new_v4();
    assert_eq!(
        test.request("GET", &path, Value::Null, Some((unrelated, false)))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        test.request(
            "POST",
            &format!("{path}/cancel"),
            json!({}),
            Some((unrelated, false))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (_, body) = test
        .request(
            "GET",
            "/internal/reviews",
            Value::Null,
            Some((unrelated, false)),
        )
        .await;
    assert_eq!(body, json!([]));
    test.finish().await;
}

#[tokio::test]
async fn concurrent_polls_share_one_compute_slot_and_replays_do_not_extend_leases() {
    let test = TestApp::new().await;
    test.review(Uuid::new_v4()).await;
    test.review(Uuid::new_v4()).await;
    let keys = [
        DeviceKey::from_bytes(&[54; 32]),
        DeviceKey::from_bytes(&[55; 32]),
    ];
    let ids = [test.online(&keys[0]).await, test.online(&keys[1]).await];
    let (a, b) = tokio::join!(
        test.work(&keys[0], ids[0], 1),
        test.work(&keys[1], ids[1], 1)
    );
    assert_eq!(usize::from(a.is_some()) + usize::from(b.is_some()), 1);
    let winner = if a.is_some() { 0 } else { 1 };
    let assignment = a.or(b).unwrap();
    let retry = test.work(&keys[winner], ids[winner], 1).await.unwrap();
    assert_eq!(retry.lease_id, assignment.lease_id);
    assert_eq!(retry.expires_at, assignment.expires_at);
    // A new signed poll also returns the current assignment without extending it.
    let retry = test.work(&keys[winner], ids[winner], 2).await.unwrap();
    assert_eq!(retry.expires_at, assignment.expires_at);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM work_leases WHERE state = 'active'")
        .fetch_one(&test.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let stale = test
        .signed(
            &keys[winner],
            &format!("/v1/devices/{}/work/poll", ids[winner]),
            WorkPoll {
                sequence: 1,
                website_reviews: false,
                source_reviews: false,
                live_tests: false,
                live_tools: vec![],
            },
        )
        .await;
    assert_eq!(stale.0, StatusCode::CONFLICT);
    test.finish().await;
}

#[tokio::test]
async fn expired_attempt_is_replaced_and_its_late_result_cannot_finish_the_new_attempt() {
    let test = TestApp::new().await;
    test.review(Uuid::new_v4()).await;
    let key = DeviceKey::from_bytes(&[56; 32]);
    let id = test.online(&key).await;
    let first = test.work(&key, id, 1).await.unwrap();
    sqlx::query("UPDATE work_leases SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(first.lease_id)
        .execute(&test.pool)
        .await
        .unwrap();
    let next = test.work(&key, id, 2).await.unwrap();
    assert_ne!(first.lease_id, next.lease_id);
    assert_eq!(first.role, next.role);
    let late = test
        .complete_work(&key, id, first.lease_id, fixture_result())
        .await;
    assert_eq!(late.0, StatusCode::CONFLICT);
    let valid = test
        .complete_work(&key, id, next.lease_id, fixture_result())
        .await;
    assert_eq!(valid.0, StatusCode::OK);
    let retry = test
        .complete_work(&key, id, next.lease_id, fixture_result())
        .await;
    assert_eq!(retry.0, StatusCode::OK);
    assert_eq!(retry.1["replayed"], true);
    let mut altered = fixture_result();
    altered.runs[0].checks[1].actual = false;
    assert_eq!(
        test.complete_work(&key, id, next.lease_id, altered).await.0,
        StatusCode::CONFLICT
    );
    let attempts: i32 =
        sqlx::query_scalar("SELECT attempts FROM review_steps WHERE role = 'investigator'")
            .fetch_one(&test.pool)
            .await
            .unwrap();
    assert_eq!(attempts, 2);
    test.finish().await;
}

#[tokio::test]
async fn private_report_counts_exclude_expired_work_and_count_replayed_incomplete_reports_once() {
    let test = TestApp::new().await;
    let key = DeviceKey::from_bytes(&[76; 32]);
    let id = test.online(&key).await;
    let unused = test.paired(&DeviceKey::from_bytes(&[77; 32])).await;
    let other_owner = Uuid::new_v4();
    let pairing = test.start(&DeviceKey::from_bytes(&[78; 32])).await;
    let (status, other) = test.claim(&pairing.user_code, other_owner).await;
    assert_eq!(status, StatusCode::OK);
    let other_id = other["device_id"].clone();
    test.review(Uuid::new_v4()).await;
    let first = test.work(&key, id, 1).await.unwrap();
    let (_, initial) = test
        .request(
            "GET",
            "/internal/devices",
            Value::Null,
            Some((test.owner, false)),
        )
        .await;
    assert_eq!(initial.as_array().unwrap().len(), 2);
    assert!(
        initial
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["reports_received"] == 0)
    );

    sqlx::query("UPDATE work_leases SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(first.lease_id)
        .execute(&test.pool)
        .await
        .unwrap();
    let replacement = test.work(&key, id, 2).await.unwrap();
    assert_eq!(
        test.complete_work(&key, id, first.lease_id, fixture_result())
            .await
            .0,
        StatusCode::CONFLICT
    );
    let mut incomplete = fixture_result();
    incomplete.runs[0].checks[1].actual = false;
    let accepted = test
        .complete_work(&key, id, replacement.lease_id, incomplete.clone())
        .await;
    assert_eq!(accepted.0, StatusCode::OK);
    assert_eq!(accepted.1["fixture_matches"], false);
    let replay = test
        .complete_work(&key, id, replacement.lease_id, incomplete)
        .await;
    assert_eq!(replay.0, StatusCode::OK);
    assert_eq!(replay.1["replayed"], true);

    for (actor, expected_length) in [
        (Some((test.owner, false)), 2),
        (Some((test.admin, true)), 3),
    ] {
        let (status, rows) = test
            .request("GET", "/internal/devices", Value::Null, actor)
            .await;
        assert_eq!(status, StatusCode::OK);
        let rows = rows.as_array().unwrap();
        assert_eq!(rows.len(), expected_length);
        assert_eq!(
            rows.iter().find(|row| row["id"] == id.to_string()).unwrap()["reports_received"],
            1
        );
        assert_eq!(
            rows.iter()
                .find(|row| row["id"] == unused.to_string())
                .unwrap()["reports_received"],
            0
        );
        assert!(
            rows.iter()
                .all(|row| row.get("result").is_none() && row.get("requester_id").is_none())
        );
    }
    let (status, other_rows) = test
        .request(
            "GET",
            "/internal/devices",
            Value::Null,
            Some((other_owner, false)),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(other_rows.as_array().unwrap().len(), 1);
    assert_eq!(other_rows[0]["id"], other_id);
    assert_eq!(other_rows[0]["reports_received"], 0);
    assert_eq!(
        test.request("GET", "/internal/devices", Value::Null, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (_, public) = test.request("GET", "/v1/fleet", Value::Null, None).await;
    assert!(public.get("reports_received").is_none());
    test.finish().await;
}

#[tokio::test]
async fn cancelled_or_revoked_work_cannot_submit_results_and_releases_capacity() {
    let test = TestApp::new().await;
    let review = test.review(Uuid::new_v4()).await;
    let key = DeviceKey::from_bytes(&[57; 32]);
    let id = test.online(&key).await;
    let assignment = test.work(&key, id, 1).await.unwrap();
    let cancel = test
        .request(
            "POST",
            &format!("/internal/reviews/{}/cancel", review.id),
            json!({}),
            Some((test.owner, false)),
        )
        .await;
    assert_eq!(cancel.0, StatusCode::OK);
    assert_eq!(cancel.1["state"], "cancelled");
    assert_eq!(
        test.complete_work(&key, id, assignment.lease_id, fixture_result())
            .await
            .0,
        StatusCode::CONFLICT
    );
    test.review(Uuid::new_v4()).await;
    let assignment = test.work(&key, id, 2).await.unwrap();
    let revoke = test
        .request(
            "POST",
            &format!("/internal/devices/{id}/decision"),
            json!({"action":"revoke","reason":"Test"}),
            Some((test.owner, false)),
        )
        .await;
    assert_eq!(revoke.0, StatusCode::OK);
    assert_eq!(
        test.complete_work(&key, id, assignment.lease_id, fixture_result())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    test.request(
        "GET",
        "/internal/reviews",
        Value::Null,
        Some((test.owner, false)),
    )
    .await;
    let active: i64 = sqlx::query_scalar("SELECT count(*) FROM work_leases WHERE state = 'active'")
        .fetch_one(&test.pool)
        .await
        .unwrap();
    assert_eq!(active, 0);
    test.finish().await;
}

#[tokio::test]
async fn queue_capacity_unsupported_targets_and_ineligible_devices_fail_before_assignment() {
    let test = TestApp::new().await;
    for _ in 0..3 {
        test.review(Uuid::new_v4()).await;
    }
    let full = test
        .request(
            "POST",
            "/internal/reviews",
            json!({"request_id":Uuid::new_v4(),"scenario":"access_control_v1"}),
            Some((test.owner, false)),
        )
        .await;
    assert_eq!(full.0, StatusCode::TOO_MANY_REQUESTS);
    let forbidden = test.request("POST","/internal/reviews",json!({"request_id":Uuid::new_v4(),"scenario":"access_control_v1","url":"https://unrelated.example"}),Some((test.owner,false))).await;
    assert_eq!(forbidden.0, StatusCode::UNPROCESSABLE_ENTITY);
    let anonymous = test
        .request(
            "POST",
            "/internal/reviews",
            json!({"request_id":Uuid::new_v4(),"scenario":"access_control_v1"}),
            None,
        )
        .await;
    assert_eq!(anonymous.0, StatusCode::UNAUTHORIZED);
    let key = DeviceKey::from_bytes(&[58; 32]);
    let id = test.paired(&key).await;
    assert_eq!(
        test.signed(
            &key,
            &format!("/v1/devices/{id}/work/poll"),
            WorkPoll {
                sequence: 1,
                website_reviews: false,
                source_reviews: false,
                live_tests: false,
                live_tools: vec![],
            }
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    test.approve(id).await;
    assert!(
        test.work(&key, id, 1).await.is_none(),
        "an offline device is not eligible"
    );
    test.signed(
        &key,
        &format!("/v1/devices/{id}/heartbeat"),
        Heartbeat {
            system: None,
            sequence: 1,
            paused: true,
            running: 0,
        },
    )
    .await;
    assert!(
        test.work(&key, id, 2).await.is_none(),
        "a paused device is not eligible"
    );
    let wrong_key = DeviceKey::from_bytes(&[59; 32]);
    assert_eq!(
        test.signed(
            &wrong_key,
            &format!("/v1/devices/{id}/work/poll"),
            WorkPoll {
                sequence: 3,
                website_reviews: false,
                source_reviews: false,
                live_tests: false,
                live_tools: vec![],
            }
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    test.finish().await;
}

#[tokio::test]
async fn missing_workers_exhaust_a_bounded_retry_budget_without_a_success_report() {
    let test = TestApp::new().await;
    let review = test.review(Uuid::new_v4()).await;
    let key = DeviceKey::from_bytes(&[60; 32]);
    let id = test.online(&key).await;
    for sequence in 1..=3 {
        let assignment = test.work(&key, id, sequence).await.unwrap();
        sqlx::query(
            "UPDATE work_leases SET expires_at = now() - interval '1 second' WHERE id = $1",
        )
        .bind(assignment.lease_id)
        .execute(&test.pool)
        .await
        .unwrap();
    }
    assert!(test.work(&key, id, 4).await.is_none());
    let response = test
        .request(
            "GET",
            &format!("/internal/reviews/{}", review.id),
            Value::Null,
            Some((test.owner, false)),
        )
        .await;
    assert_eq!(response.1["state"], "failed");
    assert_eq!(response.1["steps"][0]["attempts"], 3);
    assert_eq!(response.1["steps"][0]["state"], "failed");
    assert_eq!(response.1["steps"][1]["state"], "cancelled");
    test.finish().await;
}

#[tokio::test]
async fn conflicting_fixture_evidence_stays_needs_review_after_all_roles_report() {
    let test = TestApp::new().await;
    let review = test.review(Uuid::new_v4()).await;
    for seed in 61..64 {
        let key = DeviceKey::from_bytes(&[seed; 32]);
        let id = test.online(&key).await;
        let assignment = test.work(&key, id, 1).await.unwrap();
        let mut result = fixture_result();
        if seed == 62 {
            result.runs[0].checks[1].actual = false;
        }
        assert_eq!(
            test.complete_work(&key, id, assignment.lease_id, result)
                .await
                .0,
            StatusCode::OK
        );
    }
    let response = test
        .request(
            "GET",
            &format!("/internal/reviews/{}", review.id),
            Value::Null,
            Some((test.owner, false)),
        )
        .await;
    assert_eq!(response.1["state"], "needs_review");
    assert_eq!(response.1["steps"][1]["fixture_matches"], false);
    assert!(
        response.1["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["state"] == "completed")
    );
    test.finish().await;
}

fn agent_result() -> AgentResult {
    AgentResult {
        kind: AgentResultKind::OwnedAgentV1,
        outcome: AgentOutcome::Passed,
        declared_model: "test-local-model".into(),
        model: "test-serving-profile".into(),
        model_digest: "a".repeat(64),
        image_digest: format!("sha256:{}", "b".repeat(64)),
        duration_ms: 500_000,
        inference_calls: 2,
        terminal_calls: 1,
        cleanup_confirmed: true,
        observation: Some(AgentFixtureObservation {
            original: AgentFixtureCheck {
                owner_reads: true,
                blocks_other_user: false,
            },
            patched: AgentFixtureCheck {
                owner_reads: true,
                blocks_other_user: true,
            },
        }),
        summary: "Observed the original failure and the supplied patch passing.".into(),
    }
}

#[tokio::test]
async fn agent_reviews_bind_runtime_result_kind_and_declared_model() {
    let test = TestApp::new().await;
    let review = test.agent_review().await;
    assert_eq!(review.mode, "owned_agent");
    assert_eq!(review.deadline_at - review.created_at, 35 * 60);
    let conflict = test
        .request(
            "POST",
            "/internal/reviews",
            json!({"request_id":review.request_id, "scenario":"access_control_v1"}),
            Some((test.owner, false)),
        )
        .await;
    assert_eq!(conflict.0, StatusCode::CONFLICT);
    let fixture_key = DeviceKey::from_bytes(&[70; 32]);
    let fixture_device = test.online(&fixture_key).await;
    assert!(test.work(&fixture_key, fixture_device, 1).await.is_none());

    for seed in 71..74 {
        let key = DeviceKey::from_bytes(&[seed; 32]);
        let id = test.agent(&key, test.owner).await;
        let assignment = test.work(&key, id, 1).await.unwrap();
        assert_eq!(assignment.mode, ReviewMode::OwnedAgent);
        assert_eq!(assignment.review_id, review.id);
        assert_eq!(
            test.complete_work(&key, id, assignment.lease_id, fixture_result())
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
        let path = format!("/v1/devices/{id}/work/complete");
        let mut result = agent_result();
        result.declared_model = "unpaired-model".into();
        assert_eq!(
            test.signed(
                &key,
                &path,
                CompleteWork {
                    lease_id: assignment.lease_id,
                    result: WorkResult::Agent(result)
                }
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let body = CompleteWork {
            lease_id: assignment.lease_id,
            result: WorkResult::Agent(agent_result()),
        };
        let response = test.signed(&key, &path, &body).await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        assert_eq!(response.1["fixture_matches"], true);
        let replay = test.signed(&key, &path, &body).await;
        assert_eq!(replay.0, StatusCode::OK);
        assert_eq!(replay.1["replayed"], true);
        assert_eq!(
            test.renew(&key, id, assignment.lease_id, 1).await.0,
            StatusCode::CONFLICT
        );
        assert!(test.work(&key, id, 2).await.is_none());
    }
    let path = format!("/internal/reviews/{}", review.id);
    let response = test
        .request("GET", &path, Value::Null, Some((test.owner, false)))
        .await;
    assert_eq!(response.1["state"], "completed");
    assert_eq!(
        response.1["evidence_source"],
        "agent_reported_owned_example_not_independently_verified"
    );
    assert_eq!(response.1["steps"][0]["result"]["kind"], "owned_agent_v1");
    assert_eq!(
        test.request("GET", &path, Value::Null, Some((Uuid::new_v4(), false)))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    // Hermes cannot consume fixture work either.
    test.review(Uuid::new_v4()).await;
    let key = DeviceKey::from_bytes(&[74; 32]);
    let id = test.agent(&key, test.owner).await;
    assert!(test.work(&key, id, 1).await.is_none());
    assert!(test.work(&fixture_key, fixture_device, 2).await.is_some());
    test.finish().await;
}

#[tokio::test]
async fn renewal_replay_is_read_only_and_fresh_sequences_stop_at_the_fixed_deadline() {
    let test = TestApp::new().await;
    test.agent_review().await;
    let key = DeviceKey::from_bytes(&[75; 32]);
    let id = test.agent(&key, test.owner).await;
    let work = test.work(&key, id, 1).await.unwrap();
    sqlx::query("UPDATE work_leases SET expires_at = now() + interval '20 seconds' WHERE id = $1")
        .bind(work.lease_id)
        .execute(&test.pool)
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        test.renew(&key, id, work.lease_id, 1),
        test.renew(&key, id, work.lease_id, 1)
    );
    assert_eq!(a.0, StatusCode::OK, "{}", a.1);
    assert_eq!(b.0, StatusCode::OK, "{}", b.1);
    assert_ne!(a.1["replayed"], b.1["replayed"]);
    assert_eq!(a.1["expires_at"], b.1["expires_at"]);
    let first: WorkRenewed = serde_json::from_value(a.1).unwrap();
    assert!(first.valid_for_seconds > 50 && first.valid_for_seconds <= 60);
    assert!(first.deadline_at - first.expires_at <= 540);
    assert!(first.deadline_at - first.expires_at >= 535);

    // Advance expiry without sleeping: a duplicate must report the remaining
    // time, not hand the client another minute from its receive time.
    sqlx::query("UPDATE work_leases SET expires_at = now() + interval '10 seconds' WHERE id = $1")
        .bind(work.lease_id)
        .execute(&test.pool)
        .await
        .unwrap();
    let replay = test.renew(&key, id, work.lease_id, 1).await;
    assert_eq!(replay.0, StatusCode::OK);
    assert_eq!(replay.1["replayed"], true);
    assert!(replay.1["valid_for_seconds"].as_u64().unwrap() <= 10);
    sqlx::query("UPDATE work_leases SET deadline_at = now() + interval '20 seconds' WHERE id = $1")
        .bind(work.lease_id)
        .execute(&test.pool)
        .await
        .unwrap();
    let renewed = test.renew(&key, id, work.lease_id, 2).await;
    assert_eq!(renewed.0, StatusCode::OK);
    assert_eq!(renewed.1["expires_at"], renewed.1["deadline_at"]);
    assert!(renewed.1["valid_for_seconds"].as_u64().unwrap() <= 20);
    assert_eq!(
        test.renew(&key, id, work.lease_id, 1).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        test.renew(&key, id, work.lease_id, 0).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        test.renew(&key, id, work.lease_id, u64::MAX).await.0,
        StatusCode::BAD_REQUEST
    );
    test.finish().await;
}

#[tokio::test]
async fn renewal_cannot_revive_paused_stale_expired_replaced_cancelled_or_revoked_work() {
    let test = TestApp::new().await;
    let review = test.agent_review().await;
    let key = DeviceKey::from_bytes(&[76; 32]);
    let other_key = DeviceKey::from_bytes(&[77; 32]);
    let id = test.agent(&key, test.owner).await;
    let other_id = test.agent(&other_key, test.owner).await;
    let first = test.work(&key, id, 1).await.unwrap();
    assert_eq!(
        test.renew(&other_key, id, first.lease_id, 1).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        test.renew(&other_key, other_id, first.lease_id, 1).await.0,
        StatusCode::UNAUTHORIZED
    );
    let heartbeat_path = format!("/v1/devices/{id}/heartbeat");
    test.signed(
        &key,
        &heartbeat_path,
        Heartbeat {
            system: None,
            sequence: 2,
            paused: true,
            running: 1,
        },
    )
    .await;
    assert_eq!(
        test.renew(&key, id, first.lease_id, 1).await.0,
        StatusCode::CONFLICT
    );
    test.signed(
        &key,
        &heartbeat_path,
        Heartbeat {
            system: None,
            sequence: 3,
            paused: false,
            running: 1,
        },
    )
    .await;
    sqlx::query("UPDATE devices SET last_seen_at = now() - interval '31 seconds' WHERE id = $1")
        .bind(id)
        .execute(&test.pool)
        .await
        .unwrap();
    assert_eq!(
        test.renew(&key, id, first.lease_id, 1).await.0,
        StatusCode::CONFLICT
    );
    test.signed(
        &key,
        &heartbeat_path,
        Heartbeat {
            system: None,
            sequence: 4,
            paused: false,
            running: 1,
        },
    )
    .await;
    assert_eq!(
        test.renew(&key, id, first.lease_id, 1).await.0,
        StatusCode::OK
    );
    sqlx::query("UPDATE work_leases SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(first.lease_id)
        .execute(&test.pool)
        .await
        .unwrap();
    assert_eq!(
        test.renew(&key, id, first.lease_id, 2).await.0,
        StatusCode::CONFLICT
    );
    let next = test.work(&key, id, 2).await.unwrap();
    assert_ne!(next.lease_id, first.lease_id);
    assert_eq!(
        test.renew(&key, id, first.lease_id, 2).await.0,
        StatusCode::CONFLICT
    );
    test.request(
        "POST",
        &format!("/internal/reviews/{}/cancel", review.id),
        json!({}),
        Some((test.owner, false)),
    )
    .await;
    assert_eq!(
        test.renew(&key, id, next.lease_id, 1).await.0,
        StatusCode::CONFLICT
    );
    test.agent_review().await;
    let next = test.work(&key, id, 3).await.unwrap();
    test.request(
        "POST",
        &format!("/internal/devices/{id}/decision"),
        json!({"action":"revoke", "reason":"Test revocation"}),
        Some((test.owner, false)),
    )
    .await;
    assert_eq!(
        test.renew(&key, id, next.lease_id, 1).await.0,
        StatusCode::FORBIDDEN
    );
    test.finish().await;
}

#[tokio::test]
async fn renewals_cannot_extend_the_review_or_a_fixture_attempt() {
    let test = TestApp::new().await;
    let review = test.agent_review().await;
    let key = DeviceKey::from_bytes(&[78; 32]);
    let id = test.agent(&key, test.owner).await;
    let work = test.work(&key, id, 1).await.unwrap();
    sqlx::query("UPDATE reviews SET deadline_at = now() + interval '15 seconds' WHERE id = $1")
        .bind(review.id)
        .execute(&test.pool)
        .await
        .unwrap();
    let response = test.renew(&key, id, work.lease_id, 1).await;
    assert_eq!(response.0, StatusCode::OK);
    assert!(response.1["valid_for_seconds"].as_u64().unwrap() <= 15);
    assert_eq!(response.1["expires_at"], response.1["deadline_at"]);
    sqlx::query("UPDATE reviews SET deadline_at = now() - interval '1 second' WHERE id = $1")
        .bind(review.id)
        .execute(&test.pool)
        .await
        .unwrap();
    assert_eq!(
        test.renew(&key, id, work.lease_id, 2).await.0,
        StatusCode::CONFLICT
    );
    assert!(test.work(&key, id, 2).await.is_none());
    let response = test
        .request(
            "GET",
            &format!("/internal/reviews/{}", review.id),
            Value::Null,
            Some((test.owner, false)),
        )
        .await;
    assert_eq!(response.1["state"], "failed");

    test.review(Uuid::new_v4()).await;
    let key = DeviceKey::from_bytes(&[79; 32]);
    let id = test.online(&key).await;
    let work = test.work(&key, id, 1).await.unwrap();
    let renewed = test.renew(&key, id, work.lease_id, 1).await;
    assert_eq!(renewed.0, StatusCode::OK);
    assert_eq!(renewed.1["expires_at"].as_i64(), Some(work.expires_at));
    assert_eq!(renewed.1["deadline_at"].as_i64(), Some(work.expires_at));
    test.finish().await;
}

#[tokio::test]
async fn compute_group_names_cannot_reserve_another_operators_capacity() {
    let test = TestApp::new().await;
    test.agent_review().await;
    test.agent_review().await;
    let a = DeviceKey::from_bytes(&[80; 32]);
    let b = DeviceKey::from_bytes(&[81; 32]);
    let a_id = test.agent(&a, test.owner).await;
    let b_id = test.agent(&b, Uuid::new_v4()).await;
    let (a_work, b_work) = tokio::join!(test.work(&a, a_id, 1), test.work(&b, b_id, 1));
    assert!(a_work.is_some() && b_work.is_some());
    assert_ne!(a_work.unwrap().review_id, b_work.unwrap().review_id);
    let fleet = test.request("GET", "/v1/fleet", Value::Null, None).await;
    assert_eq!(fleet.0, StatusCode::OK);
    assert_eq!(fleet.1["online_operators"], 2);
    assert_eq!(fleet.1["online_compute_groups"], 2);
    test.finish().await;
}

#[tokio::test]
async fn confident_agent_prose_without_tool_observations_stays_needs_review() {
    let test = TestApp::new().await;
    let review = test.agent_review().await;
    for seed in 82..85 {
        let key = DeviceKey::from_bytes(&[seed; 32]);
        let id = test.agent(&key, test.owner).await;
        let work = test.work(&key, id, 1).await.unwrap();
        let mut result = agent_result();
        if seed == 83 {
            result.observation = None;
            result.terminal_calls = 0;
        }
        let response = test
            .signed(
                &key,
                &format!("/v1/devices/{id}/work/complete"),
                CompleteWork {
                    lease_id: work.lease_id,
                    result: WorkResult::Agent(result),
                },
            )
            .await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        assert_eq!(response.1["fixture_matches"], seed != 83);
    }
    let response = test
        .request(
            "GET",
            &format!("/internal/reviews/{}", review.id),
            Value::Null,
            Some((test.owner, false)),
        )
        .await;
    assert_eq!(response.1["state"], "needs_review");
    assert_eq!(response.1["steps"][1]["fixture_matches"], false);
    test.finish().await;
}

#[tokio::test]
async fn a_hard_deadline_ends_work_even_with_a_recent_heartbeat_and_unexpired_soft_lease() {
    let test = TestApp::new().await;
    test.agent_review().await;
    let key = DeviceKey::from_bytes(&[85; 32]);
    let id = test.agent(&key, test.owner).await;
    let work = test.work(&key, id, 1).await.unwrap();
    sqlx::query("UPDATE work_leases SET deadline_at = now() - interval '1 second' WHERE id = $1")
        .bind(work.lease_id)
        .execute(&test.pool)
        .await
        .unwrap();
    assert_eq!(
        test.renew(&key, id, work.lease_id, 1).await.0,
        StatusCode::CONFLICT
    );
    let result = CompleteWork {
        lease_id: work.lease_id,
        result: WorkResult::Agent(agent_result()),
    };
    assert_eq!(
        test.signed(&key, &format!("/v1/devices/{id}/work/complete"), result)
            .await
            .0,
        StatusCode::CONFLICT
    );
    let replacement = test.work(&key, id, 2).await.unwrap();
    assert_ne!(replacement.lease_id, work.lease_id);
    test.finish().await;
}

#[tokio::test]
async fn configured_cpu_budget_is_saved_and_renewal_does_not_extend_it() {
    let mut app = TestApp::with_budget(3600).await;
    for seconds in [0, 599, 3601, u64::MAX] {
        assert!(
            AppState::new(
                app.pool.clone(),
                app.internal_key.clone(),
                "test-deployment".into()
            )
            .unwrap()
            .with_agent_attempt_seconds(seconds)
            .is_err()
        );
    }
    let fleet = app.request("GET", "/v1/fleet", json!({}), None).await;
    assert_eq!(fleet.1["agent_review_timeout_seconds"], 11100);
    let review = app.agent_review().await;
    assert_eq!(review.deadline_at - review.created_at, 11100);
    // The database also rejects an out-of-range allowance, independently of
    // configuration validation. A failed update must preserve the reservation.
    let invalid = sqlx::query("UPDATE reviews SET agent_attempt_seconds=3601 WHERE id=$1")
        .bind(review.id)
        .execute(&app.pool)
        .await
        .unwrap_err();
    assert_eq!(
        invalid.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    // New deployment defaults must not rewrite an admitted review's limits.
    app.change_budget(600);
    let key = DeviceKey::from_bytes(&[110; 32]);
    let device = app.agent(&key, app.owner).await;
    let work = app.work(&key, device, 1).await.unwrap();
    let duration: i64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM deadline_at - created_at)::bigint FROM work_leases WHERE id=$1",
    )
    .bind(work.lease_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(duration, 3600);
    let first = app.renew(&key, device, work.lease_id, 1).await;
    let second = app.renew(&key, device, work.lease_id, 2).await;
    assert_eq!(first.0, StatusCode::OK);
    assert_eq!(first.1["deadline_at"], second.1["deadline_at"]);
    app.request(
        "POST",
        &format!("/internal/reviews/{}/cancel", review.id),
        json!({}),
        Some((app.owner, false)),
    )
    .await;
    assert_eq!(
        app.renew(&key, device, work.lease_id, 3).await.0,
        StatusCode::CONFLICT
    );
    app.finish().await;
}
