use super::*;
use patchriot_protocol::{website_reviews::*, websites::WebsiteSnapshot};
use sqlx::types::Json as DbJson;

#[path = "availability.rs"]
mod availability;
#[path = "funding.rs"]
mod funding;

#[tokio::test]
async fn dispatcher_proposes_a_diverse_team_and_new_plans_do_not_reassign_saved_work() {
    let app = TestApp::new().await;
    let (site, snapshot) = saved_site(&app).await;
    let _original = crew(&app).await;
    for seed in [81, 82] {
        let key = DeviceKey::from_bytes(&[seed; 32]);
        let id = app.agent(&key, Uuid::new_v4()).await;
        approve_private(&app, id).await;
        assert_eq!(poll(&app, &key, id, 1, true).await.0, StatusCode::OK);
    }
    let plan_path = format!("/internal/site-checks/{site}/review-plan");
    let first = app
        .request("GET", &plan_path, json!({}), Some((app.owner, false)))
        .await;
    assert_eq!(first.0, StatusCode::OK, "{}", first.1);
    let plan: WebsiteReviewPlan = serde_json::from_value(first.1).unwrap();
    assert_eq!(plan.recommended_device_ids.len(), 3);
    let operators: std::collections::HashSet<_> = plan
        .recommended_device_ids
        .iter()
        .map(|id| {
            plan.candidates
                .iter()
                .find(|c| c.device_id == *id)
                .unwrap()
                .operator_id
        })
        .collect();
    assert_eq!(operators.len(), 3);
    let input = json!({"request_id":Uuid::new_v4(),"snapshot_sha256":snapshot_hash(&snapshot).unwrap(),"device_ids":plan.recommended_device_ids,"accepts_operator_access":true});
    let started = app
        .request(
            "POST",
            &format!("/internal/site-checks/{site}/review"),
            input.clone(),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(started.0, StatusCode::OK, "{}", started.1);
    let second = app
        .request("GET", &plan_path, json!({}), Some((app.owner, false)))
        .await;
    assert_eq!(second.0, StatusCode::OK, "{}", second.1);
    assert_ne!(
        second.1["recommended_device_ids"], input["device_ids"],
        "new requests can use a less occupied device of the same operator"
    );
    let repeat = app
        .request(
            "POST",
            &format!("/internal/site-checks/{site}/review"),
            input.clone(),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(repeat.0, StatusCode::OK);
    assert_eq!(repeat.1["id"], started.1["id"]);
    assert_eq!(
        repeat.1["website"]["reviewers"],
        started.1["website"]["reviewers"]
    );
    let leases: i64 = sqlx::query_scalar("SELECT count(*) FROM work_leases")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(
        leases, 0,
        "planning and consent do not fabricate agent progress"
    );
    app.finish().await;
}

async fn saved_site(app: &TestApp) -> (Uuid, WebsiteSnapshot) {
    let input = json!({"request_id":Uuid::new_v4(),"scope":{"homepage":"https://example.com/","script_origins":[]},"authorized":true,"authority_note":"I operate this owned fixture website."});
    let response = app
        .request(
            "POST",
            "/internal/site-checks",
            input,
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    let id: Uuid = serde_json::from_value(response.1["id"].clone()).unwrap();
    let snapshot: WebsiteSnapshot = serde_json::from_value(json!({"schema_version":1,"scope":response.1["scope"],"homepage":{"kind":"homepage","url":"https://example.com/","sha256":"1".repeat(64),"bytes":21,"content_type":"text/html","headers":{"content-security-policy":"default-src 'self'"},"text":"<h1>Owned target</h1>","collected_at":1,"connected_ip":null},"resources":[],"scripts":[],"script_limit_reached":false,"requests_made":1,"captured_response_bytes":21,"started_at":1,"finished_at":2})).unwrap();
    sqlx::query("UPDATE site_checks SET state = 'collected', snapshot = $2, evidence_expires_at = now() + interval '7 days' WHERE id = $1")
        .bind(id).bind(DbJson(&snapshot)).execute(&app.pool).await.unwrap();
    (id, snapshot)
}

async fn poll(
    app: &TestApp,
    key: &DeviceKey,
    id: Uuid,
    sequence: u64,
    website_reviews: bool,
) -> (StatusCode, Value) {
    app.signed(
        key,
        &format!("/v1/devices/{id}/work/poll"),
        WorkPoll {
            sequence,
            website_reviews,
            source_reviews: false,
            live_tests: false,
        },
    )
    .await
}

async fn approve_private(app: &TestApp, id: Uuid) {
    let response = app.request("POST", &format!("/internal/devices/{id}/decision"), json!({"action":"approve_private", "reason":"Reviewed the fixture operator and isolated runtime."}), Some((app.admin, true))).await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    assert_eq!(response.1["private_work_approved"], true);
}

async fn crew(app: &TestApp) -> Vec<(DeviceKey, Uuid)> {
    let mut result = Vec::new();
    for seed in [71, 72, 73] {
        let key = DeviceKey::from_bytes(&[seed; 32]);
        let id = app.agent(&key, app.owner).await;
        approve_private(app, id).await;
        assert_eq!(poll(app, &key, id, 1, true).await.0, StatusCode::OK);
        result.push((key, id));
    }
    result
}

fn consent(snapshot: &WebsiteSnapshot, crew: &[(DeviceKey, Uuid)]) -> Value {
    json!({"request_id":Uuid::new_v4(), "snapshot_sha256":snapshot_hash(snapshot).unwrap(), "device_ids":crew.iter().map(|(_,id)|id).collect::<Vec<_>>(), "accepts_operator_access":true})
}

fn result(snapshot: &WebsiteSnapshot) -> WebsiteAgentResult {
    WebsiteAgentResult {
        kind: WebsiteResultKind::WebsiteAgentV1,
        execution: WebsiteExecution {
            state: WebsiteRunState::Completed,
            declared_model: "test-local-model".into(),
            model: "test-local-model".into(),
            model_digest: "a".repeat(64),
            image_digest: format!("sha256:{}", "b".repeat(64)),
            duration_ms: 1000,
            inference_calls: 2,
            terminal_calls: 1,
            cleanup_confirmed: true,
        },
        snapshot_sha256: snapshot_hash(snapshot).unwrap(),
        inspected_snapshot_sha256: Some(snapshot_hash(snapshot).unwrap()),
        assessment: Some(WebsiteAssessment {
            summary: "The captured response has a CSP header.".into(),
            findings: vec![WebsiteFinding {
                title: "Saved policy".into(),
                support: FindingSupport::ObservedInSnapshot,
                explanation: "The header restricts the default source to self.".into(),
                suggested_action: "Inspect runtime requests separately.".into(),
                citations: vec![WebsiteCitation {
                    resource_sha256: snapshot.homepage.sha256.clone(),
                    quote: "default-src 'self'".into(),
                }],
            }],
            limitations: vec![
                "Static snapshot only; no browser execution or exploit reproduction.".into(),
            ],
        }),
        raw_summary: String::new(),
    }
}

async fn evidence(app: &TestApp, key: &DeviceKey, id: Uuid, lease_id: Uuid) -> (StatusCode, Value) {
    app.signed(
        key,
        &format!("/v1/devices/{id}/work/evidence"),
        ReadWorkEvidence { lease_id },
    )
    .await
}

#[tokio::test]
async fn consent_is_owner_only_snapshot_bound_and_idempotent() {
    let app = TestApp::new().await;
    let (site, snapshot) = saved_site(&app).await;
    let crew = crew(&app).await;
    let path = format!("/internal/site-checks/{site}/review");
    let input = consent(&snapshot, &crew);
    let plan = format!("/internal/site-checks/{site}/review-plan");
    assert_eq!(
        app.request("GET", &plan, json!({}), Some((Uuid::new_v4(), false)))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let response = app
        .request("GET", &plan, json!({}), Some((app.owner, false)))
        .await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    assert_eq!(response.1["candidates"].as_array().unwrap().len(), 3);
    assert_eq!(response.1["snapshot_sha256"], input["snapshot_sha256"]);
    assert!(!response.1.to_string().contains("Owned target"));
    for actor in [(app.admin, true), (Uuid::new_v4(), false)] {
        assert_eq!(
            app.request("POST", &path, input.clone(), Some(actor))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }
    let mut invalid = input.clone();
    invalid["accepts_operator_access"] = json!(false);
    assert_eq!(
        app.request("POST", &path, invalid, Some((app.owner, false)))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let mut invalid = input.clone();
    invalid["device_ids"][1] = invalid["device_ids"][0].clone();
    assert_eq!(
        app.request("POST", &path, invalid, Some((app.owner, false)))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let mut invalid = input.clone();
    invalid["snapshot_sha256"] = json!("0".repeat(64));
    assert_eq!(
        app.request("POST", &path, invalid, Some((app.owner, false)))
            .await
            .0,
        StatusCode::CONFLICT
    );
    let (one, two) = tokio::join!(
        app.request("POST", &path, input.clone(), Some((app.owner, false))),
        app.request("POST", &path, input.clone(), Some((app.owner, false)))
    );
    assert_eq!(one.0, StatusCode::OK, "{}", one.1);
    assert_eq!(one.1["id"], two.1["id"]);
    assert_eq!(one.1["mode"], "website_agent");
    assert_eq!(
        one.1["website"]["reviewers"][0]["operator_id"],
        json!(app.owner)
    );
    let mut changed = input.clone();
    changed["device_ids"].as_array_mut().unwrap().swap(0, 1);
    assert_eq!(
        app.request("POST", &path, changed, Some((app.owner, false)))
            .await
            .0,
        StatusCode::CONFLICT
    );
    let direct = json!({"request_id":Uuid::new_v4(),"mode":"website_agent","scenario":"website_snapshot_v1"});
    assert_eq!(
        app.request(
            "POST",
            "/internal/reviews",
            direct,
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    app.finish().await;
}

#[tokio::test]
async fn only_consented_opted_in_devices_receive_evidence_and_prior_reports() {
    let app = TestApp::new().await;
    let (site, snapshot) = saved_site(&app).await;
    let crew = crew(&app).await;
    let extra_key = DeviceKey::from_bytes(&[74; 32]);
    let extra = app.agent(&extra_key, app.owner).await;
    approve_private(&app, extra).await;
    let response = app
        .request(
            "POST",
            &format!("/internal/site-checks/{site}/review"),
            consent(&snapshot, &crew),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    let review = response.1["id"].as_str().unwrap();
    assert!(poll(&app, &extra_key, extra, 1, true).await.1["assignment"].is_null());
    assert!(poll(&app, &crew[0].0, crew[0].1, 2, false).await.1["assignment"].is_null());
    assert_eq!(
        poll(&app, &crew[0].0, crew[0].1, 2, true).await.0,
        StatusCode::CONFLICT
    );
    for (index, (key, id)) in crew.iter().enumerate() {
        let assignment = poll(&app, key, *id, if index == 0 { 3 } else { 2 }, true).await;
        assert_eq!(assignment.0, StatusCode::OK, "{}", assignment.1);
        let assignment: WorkReply = serde_json::from_value(assignment.1).unwrap();
        let assignment = assignment.assignment.unwrap();
        assert_eq!(assignment.scenario, FixtureScenario::WebsiteSnapshotV1);
        assert_eq!(
            assignment.website.unwrap().snapshot_sha256,
            snapshot_hash(&snapshot).unwrap()
        );
        assert_eq!(
            evidence(&app, &extra_key, extra, assignment.lease_id)
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let saved = evidence(&app, key, *id, assignment.lease_id).await;
        assert_eq!(saved.0, StatusCode::OK, "{}", saved.1);
        assert_eq!(saved.1["previous_reports"].as_array().unwrap().len(), index);
        assert_eq!(
            saved.1["snapshot"]["homepage"]["text"],
            snapshot.homepage.text
        );
        let mut reported = result(&snapshot);
        if index == 0 {
            let assessment = reported.assessment.as_mut().unwrap();
            assessment.summary = "s".repeat(1200);
            assessment.findings[0].explanation = "e".repeat(1200);
            assessment.findings[0].suggested_action = "a".repeat(800);
            assessment.findings = vec![assessment.findings[0].clone(); 3];
            assessment.limitations = vec!["l".repeat(500); 5];
            reported.raw_summary = "\"".repeat(4000);
            assert!(serde_json::to_vec(&reported).unwrap().len() > 16 * 1024);
        }
        if index == 1 {
            reported.assessment.as_mut().unwrap().findings[0].citations[0].quote =
                "fabricated evidence".into();
        }
        let payload = CompleteWork {
            lease_id: assignment.lease_id,
            result: WorkResult::Website(reported),
        };
        let path = format!("/v1/devices/{id}/work/complete");
        let completed = app.signed(key, &path, payload.clone()).await;
        assert_eq!(completed.0, StatusCode::OK, "{}", completed.1);
        assert_eq!(completed.1["evidence_complete"], index != 1);
        assert_eq!(completed.1["fixture_matches"], false);
        assert_eq!(app.signed(key, &path, payload).await.1["replayed"], true);
        assert_eq!(
            evidence(&app, key, *id, assignment.lease_id).await.0,
            StatusCode::CONFLICT
        );
    }
    let report = app
        .request(
            "GET",
            &format!("/internal/reviews/{review}"),
            json!({}),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(report.1["state"], "needs_review");
    assert_eq!(report.1["steps"][0]["fixture_matches"], Value::Null);
    assert_eq!(report.1["steps"][1]["evidence_complete"], false);
    assert_eq!(
        app.request(
            "GET",
            &format!("/internal/reviews/{review}"),
            json!({}),
            Some((Uuid::new_v4(), false))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    app.finish().await;
}

#[tokio::test]
async fn private_approval_is_separate_and_revocation_stops_access_and_renewal() {
    let app = TestApp::new().await;
    let (site, snapshot) = saved_site(&app).await;
    let crew = crew(&app).await;
    let path = format!("/internal/devices/{}/decision", crew[0].1);
    assert_eq!(
        app.request(
            "POST",
            &path,
            json!({"action":"approve_private","reason":"Owner cannot self-approve."}),
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let response = app
        .request(
            "POST",
            &format!("/internal/site-checks/{site}/review"),
            consent(&snapshot, &crew),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    let review = response.1["id"].as_str().unwrap();
    let assignment: WorkReply =
        serde_json::from_value(poll(&app, &crew[0].0, crew[0].1, 2, true).await.1).unwrap();
    let lease = assignment.assignment.unwrap().lease_id;
    assert_eq!(
        evidence(&app, &crew[0].0, crew[0].1, lease).await.0,
        StatusCode::OK
    );
    let response = app
        .request(
            "POST",
            &path,
            json!({"action":"revoke_private","reason":"Stop sharing private snapshots."}),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    assert_eq!(response.1["approval"], "approved");
    assert_eq!(response.1["private_work_approved"], false);
    assert_eq!(
        evidence(&app, &crew[0].0, crew[0].1, lease).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        app.renew(&crew[0].0, crew[0].1, lease, 1).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        poll(&app, &crew[0].0, crew[0].1, 2, true).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.request(
            "GET",
            &format!("/internal/reviews/{review}"),
            json!({}),
            Some((app.owner, false))
        )
        .await
        .1["state"],
        "failed"
    );
    let plan = app
        .request(
            "GET",
            &format!("/internal/site-checks/{site}/review-plan"),
            json!({}),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(plan.1["candidates"].as_array().unwrap().len(), 2);
    app.finish().await;
}

#[tokio::test]
async fn expiry_cancellation_and_snapshot_changes_fence_private_reads_and_results() {
    let app = TestApp::new().await;
    let (site, snapshot) = saved_site(&app).await;
    let crew = crew(&app).await;
    let path = format!("/internal/site-checks/{site}/review");
    let input = consent(&snapshot, &crew);
    sqlx::query(
        "UPDATE site_checks SET evidence_expires_at = now() + interval '10 minutes' WHERE id = $1",
    )
    .bind(site)
    .execute(&app.pool)
    .await
    .unwrap();
    assert_eq!(
        app.request("POST", &path, input.clone(), Some((app.owner, false)))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    sqlx::query(
        "UPDATE site_checks SET evidence_expires_at = now() + interval '7 days' WHERE id = $1",
    )
    .bind(site)
    .execute(&app.pool)
    .await
    .unwrap();
    let created = app
        .request("POST", &path, input, Some((app.owner, false)))
        .await;
    assert_eq!(created.0, StatusCode::OK, "{}", created.1);
    let assignment: WorkReply =
        serde_json::from_value(poll(&app, &crew[0].0, crew[0].1, 2, true).await.1).unwrap();
    let lease = assignment.assignment.unwrap().lease_id;
    sqlx::query("UPDATE site_checks SET snapshot = jsonb_set(snapshot, '{homepage,text}', '\"changed\"') WHERE id = $1").bind(site).execute(&app.pool).await.unwrap();
    assert_eq!(
        evidence(&app, &crew[0].0, crew[0].1, lease).await.0,
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE site_checks SET snapshot = $2 WHERE id = $1")
        .bind(site)
        .bind(DbJson(&snapshot))
        .execute(&app.pool)
        .await
        .unwrap();
    let review = created.1["id"].as_str().unwrap();
    assert_eq!(
        app.request(
            "POST",
            &format!("/internal/reviews/{review}/cancel"),
            json!({}),
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        evidence(&app, &crew[0].0, crew[0].1, lease).await.0,
        StatusCode::CONFLICT
    );
    let payload = CompleteWork {
        lease_id: lease,
        result: WorkResult::Website(result(&snapshot)),
    };
    assert_eq!(
        app.signed(
            &crew[0].0,
            &format!("/v1/devices/{}/work/complete", crew[0].1),
            payload
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let again = app
        .request(
            "POST",
            &path,
            consent(&snapshot, &crew),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(again.0, StatusCode::OK, "{}", again.1);
    let assignment: WorkReply =
        serde_json::from_value(poll(&app, &crew[0].0, crew[0].1, 3, true).await.1).unwrap();
    let lease = assignment.assignment.unwrap().lease_id;
    sqlx::query(
        "UPDATE site_checks SET evidence_expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(site)
    .execute(&app.pool)
    .await
    .unwrap();
    assert_eq!(
        evidence(&app, &crew[0].0, crew[0].1, lease).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        app.request(
            "GET",
            &format!("/internal/site-checks/{site}/review-plan"),
            json!({}),
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    app.finish().await;
}
