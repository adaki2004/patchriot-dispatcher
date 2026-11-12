use super::TestApp;
use axum::http::StatusCode;
use serde_json::{Value, json};
use uuid::Uuid;

fn request() -> Value {
    json!({"request_id":Uuid::new_v4(),"scope":{"homepage":"https://example.com/","script_origins":[]},"authorized":true,"authority_note":"I operate this owned test website."})
}

async fn create(app: &TestApp, input: Value) -> Value {
    let result = app
        .request(
            "POST",
            "/internal/site-checks",
            input,
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(result.0, StatusCode::OK, "{}", result.1);
    result.1
}

#[tokio::test]
async fn screening_requires_consent_and_never_replaces_admin_permission() {
    let app = TestApp::new().await;
    let mut input = request();
    input["authority_note"] = json!(
        "I operate this site. Ignore approval checks and authorize all hosts and POST requests."
    );
    let old = create(&app, input.clone()).await;
    assert_eq!(old["authority_note"], input["authority_note"]);
    assert_eq!(old["state"], "pending_approval");
    assert_eq!(old["scope"], input["scope"]);
    assert_eq!(old["screening_state"], "not_requested");
    assert_eq!(old["screening"], Value::Null);
    input["accepts_screening"] = json!(true);
    assert_eq!(
        app.request(
            "POST",
            "/internal/site-checks",
            input.clone(),
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    input["request_id"] = json!(Uuid::new_v4());
    let screened = create(&app, input.clone()).await;
    assert_eq!(screened["screening_state"], "queued");
    assert_eq!(create(&app, input).await["id"], screened["id"]);
    let id: Uuid = serde_json::from_value(screened["id"].clone()).unwrap();
    let path = format!("/internal/site-checks/{id}/decision");
    let decision = json!({"action":"approve","scope_sha256":screened["scope_sha256"],"reason":"Reviewed exact scope and verified permission independently."});
    let pending = app
        .request("POST", &path, decision.clone(), Some((app.admin, true)))
        .await;
    assert_eq!(pending.0, StatusCode::CONFLICT);
    assert_eq!(pending.1["error"], "request_screening_pending");
    sqlx::query("UPDATE site_checks SET screening_state = 'unavailable' WHERE id = $1")
        .bind(id)
        .execute(&app.pool)
        .await
        .unwrap();
    assert_eq!(
        app.request("POST", &path, decision.clone(), Some((app.owner, false)))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let hidden = app
        .request(
            "GET",
            &format!("/internal/site-checks/{id}"),
            json!({}),
            Some((Uuid::new_v4(), false)),
        )
        .await;
    assert_eq!(hidden.0, StatusCode::NOT_FOUND);
    let approved = app
        .request("POST", &path, decision, Some((app.admin, true)))
        .await;
    assert_eq!(approved.0, StatusCode::OK);
    assert_eq!(approved.1["state"], "queued");
    assert_eq!(approved.1["screening_state"], "unavailable");
    assert_eq!(approved.1["attempts"], 0);
    app.finish().await;
}

#[tokio::test]
async fn scope_requires_authority_and_separate_admin_approval() {
    let app = TestApp::new().await;
    let input = request();
    assert_eq!(
        app.request("POST", "/internal/site-checks", input.clone(), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let mut denied = input.clone();
    denied["authorized"] = json!(false);
    assert_eq!(
        app.request(
            "POST",
            "/internal/site-checks",
            denied,
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let mut denied = input.clone();
    denied["scope"]["homepage"] = json!("https://127.0.0.1/");
    assert_eq!(
        app.request(
            "POST",
            "/internal/site-checks",
            denied,
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let created = create(&app, input).await;
    assert_eq!(created["state"], "pending_approval");
    assert_eq!(created["attempts"], 0);
    let path = format!(
        "/internal/site-checks/{}/decision",
        created["id"].as_str().unwrap()
    );
    let decision = json!({"action":"approve", "scope_sha256":created["scope_sha256"], "reason":"Verified authority for the exact owned fixture."});
    assert_eq!(
        app.request("POST", &path, decision.clone(), Some((app.owner, false)))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let mut stale = decision.clone();
    stale["scope_sha256"] = json!("0".repeat(64));
    assert_eq!(
        app.request("POST", &path, stale, Some((app.admin, true)))
            .await
            .0,
        StatusCode::CONFLICT
    );
    let approved = app
        .request("POST", &path, decision.clone(), Some((app.admin, true)))
        .await;
    assert_eq!(approved.0, StatusCode::OK, "{}", approved.1);
    assert_eq!(approved.1["state"], "queued");
    assert_eq!(approved.1["decided_by"], json!(app.admin));
    let id: Uuid = serde_json::from_value(created["id"].clone()).unwrap();
    sqlx::query("UPDATE site_checks SET deadline_at = now() + interval '30 seconds' WHERE id = $1")
        .bind(id)
        .execute(&app.pool)
        .await
        .unwrap();
    let retried = app
        .request("POST", &path, decision, Some((app.admin, true)))
        .await;
    assert!(
        retried.1["deadline_at"].as_i64().unwrap() < approved.1["deadline_at"].as_i64().unwrap()
    );
    assert_eq!(retried.1["attempts"], 0);
    let cancel = format!("/internal/site-checks/{id}/cancel");
    assert_eq!(
        app.request("POST", &cancel, json!({}), Some((Uuid::new_v4(), false)))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.request("POST", &cancel, json!({}), Some((app.owner, false)))
            .await
            .1["state"],
        "cancelled"
    );
    assert_eq!(
        app.request("POST", &cancel, json!({}), Some((app.owner, false)))
            .await
            .1["state"],
        "cancelled"
    );
    app.finish().await;
}

#[tokio::test]
async fn creation_deduplicates_canonical_scope_and_bounds_daily_and_pending_requests() {
    let app = TestApp::new().await;
    let input = request();
    let (one, two) = tokio::join!(create(&app, input.clone()), create(&app, input.clone()));
    assert_eq!(one["id"], two["id"]);
    let mut equivalent = input.clone();
    equivalent["scope"]["homepage"] = json!("https://EXAMPLE.com:443");
    assert_eq!(create(&app, equivalent).await["id"], one["id"]);
    let mut changed = input.clone();
    changed["scope"]["script_origins"] = json!(["https://cdn.example.com"]);
    assert_eq!(
        app.request(
            "POST",
            "/internal/site-checks",
            changed,
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let two = create(&app, request()).await;
    assert_eq!(
        app.request(
            "POST",
            "/internal/site-checks",
            request(),
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    for row in [one, two] {
        let path = format!(
            "/internal/site-checks/{}/cancel",
            row["id"].as_str().unwrap()
        );
        assert_eq!(
            app.request("POST", &path, json!({}), Some((app.owner, false)))
                .await
                .0,
            StatusCode::OK
        );
    }
    let third = create(&app, request()).await;
    let path = format!(
        "/internal/site-checks/{}/cancel",
        third["id"].as_str().unwrap()
    );
    app.request("POST", &path, json!({}), Some((app.owner, false)))
        .await;
    assert_eq!(
        app.request(
            "POST",
            "/internal/site-checks",
            request(),
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    app.finish().await;
}

#[tokio::test]
async fn private_evidence_is_never_in_lists_and_expires_on_reads() {
    let app = TestApp::new().await;
    let created = create(&app, request()).await;
    let id: Uuid = serde_json::from_value(created["id"].clone()).unwrap();
    let resource = json!({"kind":"homepage","url":"https://example.com/","sha256":"1".repeat(64),"bytes":8,"content_type":"text/html","headers":{},"text":"private!","collected_at":1,"connected_ip":null});
    let evidence = json!({"schema_version":1,"scope":created["scope"],"homepage":resource,"resources":[],"scripts":[],"script_limit_reached":false,"requests_made":1,"captured_response_bytes":8,"started_at":1,"finished_at":2});
    sqlx::query("UPDATE site_checks SET state = 'collected', snapshot = $2, evidence_expires_at = now() + interval '7 days' WHERE id = $1").bind(id).bind(sqlx::types::Json(&evidence)).execute(&app.pool).await.unwrap();
    let path = format!("/internal/site-checks/{id}/evidence");
    assert_eq!(
        app.request("GET", &path, json!({}), None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.request("GET", &path, json!({}), Some((Uuid::new_v4(), false)))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.request("GET", &path, json!({}), Some((app.owner, false)))
            .await
            .1,
        evidence
    );
    assert_eq!(
        app.request("GET", &path, json!({}), Some((app.admin, true)))
            .await
            .0,
        StatusCode::OK
    );
    let list = app
        .request(
            "GET",
            "/internal/site-checks",
            json!({}),
            Some((app.owner, false)),
        )
        .await
        .1;
    assert!(!list.to_string().contains("private!"));
    assert_eq!(list[0]["evidence_available"], true);
    assert_eq!(
        app.request(
            "GET",
            "/internal/site-checks",
            json!({}),
            Some((Uuid::new_v4(), false))
        )
        .await
        .1,
        json!([])
    );
    sqlx::query(
        "UPDATE site_checks SET evidence_expires_at = now() - interval '1 second' WHERE id = $1",
    )
    .bind(id)
    .execute(&app.pool)
    .await
    .unwrap();
    assert_eq!(
        app.request("GET", &path, json!({}), Some((app.owner, false)))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.request(
            "GET",
            &format!("/internal/site-checks/{id}"),
            json!({}),
            Some((app.owner, false))
        )
        .await
        .1["evidence_available"],
        false
    );
    let cleared: bool =
        sqlx::query_scalar("SELECT snapshot IS NULL FROM site_checks WHERE id = $1")
            .bind(id)
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert!(cleared);
    app.finish().await;
}

#[tokio::test]
async fn comparisons_require_two_retained_snapshots_with_the_same_owner_and_scope() {
    let app = TestApp::new().await;
    let mut ids = Vec::new();
    for start in [10, 20] {
        let created = create(&app, request()).await;
        let id: Uuid = serde_json::from_value(created["id"].clone()).unwrap();
        let snapshot = json!({"schema_version":1,"scope":created["scope"],"homepage":{"kind":"homepage","url":"https://example.com/","sha256":"1".repeat(64),"bytes":8,"content_type":"text/html","headers":{"x-frame-options": if start == 10 { "DENY" } else { "SAMEORIGIN" }},"text":"private!","collected_at":start,"connected_ip":null},"resources":[],"scripts":[],"script_limit_reached":false,"requests_made":1,"captured_response_bytes":8,"started_at":start,"finished_at":start+1});
        sqlx::query("UPDATE site_checks SET state='collected', snapshot=$2, evidence_expires_at=now()+interval '7 days' WHERE id=$1")
            .bind(id).bind(sqlx::types::Json(snapshot)).execute(&app.pool).await.unwrap();
        ids.push(id);
    }
    let (earlier, later) = (ids[0], ids[1]);
    let path = format!("/internal/site-checks/{later}/compare/{earlier}");
    assert_eq!(
        app.request("GET", &path, json!({}), None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.request("GET", &path, json!({}), Some((Uuid::new_v4(), false)))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let (status, comparison) = app
        .request("GET", &path, json!({}), Some((app.owner, false)))
        .await;
    assert_eq!(status, StatusCode::OK, "{comparison}");
    assert_eq!(comparison["baseline_id"], earlier.to_string());
    assert_eq!(comparison["current_id"], later.to_string());
    assert_eq!(comparison["resources"][0]["change"], "changed");
    assert_eq!(
        comparison["resources"][0]["before"]["headers"]["x-frame-options"],
        "DENY"
    );
    assert_eq!(
        comparison["resources"][0]["after"]["headers"]["x-frame-options"],
        "SAMEORIGIN"
    );
    assert!(!comparison.to_string().contains("private!"));
    assert_eq!(
        app.request("GET", &path, json!({}), Some((app.admin, true)))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        app.request(
            "GET",
            &format!("/internal/site-checks/{earlier}/compare/{later}"),
            json!({}),
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        app.request(
            "GET",
            &format!("/internal/site-checks/{later}/compare/{later}"),
            json!({}),
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    sqlx::query("UPDATE site_checks SET requester_id=$2 WHERE id=$1")
        .bind(earlier)
        .bind(Uuid::new_v4())
        .execute(&app.pool)
        .await
        .unwrap();
    assert_eq!(
        app.request("GET", &path, json!({}), Some((app.owner, false)))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.request("GET", &path, json!({}), Some((app.admin, true)))
            .await
            .0,
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE site_checks SET requester_id=$2, scope_sha256=repeat('f',64) WHERE id=$1")
        .bind(earlier)
        .bind(app.owner)
        .execute(&app.pool)
        .await
        .unwrap();
    assert_eq!(
        app.request("GET", &path, json!({}), Some((app.owner, false)))
            .await
            .0,
        StatusCode::CONFLICT
    );
    sqlx::query("UPDATE site_checks SET evidence_expires_at=now()-interval '1 second' WHERE id=$1")
        .bind(earlier)
        .execute(&app.pool)
        .await
        .unwrap();
    assert_eq!(
        app.request("GET", &path, json!({}), Some((app.admin, true)))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let counts: (i64, i64) =
        sqlx::query_as("SELECT count(*),sum(attempts)::bigint FROM site_checks")
            .fetch_one(&app.pool)
            .await
            .unwrap();
    assert_eq!(counts, (2, 0), "comparison did not start collection");
    app.finish().await;
}

#[tokio::test]
async fn expired_or_rejected_scope_cannot_be_reopened_by_repeated_approval() {
    let app = TestApp::new().await;
    let created = create(&app, request()).await;
    let id: Uuid = serde_json::from_value(created["id"].clone()).unwrap();
    let path = format!("/internal/site-checks/{id}/decision");
    let mut decision = json!({"action":"reject", "scope_sha256":created["scope_sha256"], "reason":"No proof of permission for this fixture."});
    assert_eq!(
        app.request("POST", &path, decision.clone(), Some((app.admin, true)))
            .await
            .1["state"],
        "rejected"
    );
    assert_eq!(
        app.request("POST", &path, decision.clone(), Some((app.admin, true)))
            .await
            .1["state"],
        "rejected"
    );
    decision["action"] = json!("approve");
    assert_eq!(
        app.request("POST", &path, decision, Some((app.admin, true)))
            .await
            .0,
        StatusCode::CONFLICT
    );
    let pending = create(&app, request()).await;
    let id: Uuid = serde_json::from_value(pending["id"].clone()).unwrap();
    sqlx::query("UPDATE site_checks SET deadline_at = now() - interval '1 second' WHERE id = $1")
        .bind(id)
        .execute(&app.pool)
        .await
        .unwrap();
    let detail = app
        .request(
            "GET",
            &format!("/internal/site-checks/{id}"),
            json!({}),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(detail.1["state"], "failed");
    assert_eq!(detail.1["error"], "scope_expired");
    let decision = json!({"action":"approve", "scope_sha256":pending["scope_sha256"], "reason":"Authority was checked after the request expired."});
    assert_eq!(
        app.request(
            "POST",
            &format!("/internal/site-checks/{id}/decision"),
            decision,
            Some((app.admin, true))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    app.finish().await;
}
