use super::*;

async fn candidates(app: &TestApp, site: Uuid) -> Vec<Uuid> {
    let response = app
        .request(
            "GET",
            &format!("/internal/site-checks/{site}/review-plan"),
            json!({}),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    response.1["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|device| serde_json::from_value(device["device_id"].clone()).unwrap())
        .collect()
}

#[tokio::test]
async fn website_candidates_need_recent_work_poll_not_just_presence_or_replays() {
    let app = TestApp::new().await;
    let (site, _) = saved_site(&app).await;
    let crew = crew(&app).await;
    let (key, id) = &crew[0];
    assert_eq!(candidates(&app, site).await.len(), 3);
    // Simulate a restart into presence-only mode: the work poll ages while
    // fresh signed heartbeats continue. No sleep or actual runtime is needed.
    sqlx::query("UPDATE devices SET work_polled_at = now() - interval '2 minutes' WHERE id = $1")
        .bind(id)
        .execute(&app.pool)
        .await
        .unwrap();
    let heartbeat = app
        .signed(
            key,
            &format!("/v1/devices/{id}/heartbeat"),
            Heartbeat {
                sequence: 2,
                paused: false,
                running: 0,
            },
        )
        .await;
    assert_eq!(heartbeat.0, StatusCode::OK);
    assert_eq!(heartbeat.1["state"], "online");
    let after_presence = candidates(&app, site).await;
    assert_eq!(poll(&app, key, *id, 1, true).await.0, StatusCode::OK);
    let after_replay = candidates(&app, site).await;
    sqlx::query("UPDATE devices SET work_polled_at = NULL WHERE id = $1")
        .bind(id)
        .execute(&app.pool)
        .await
        .unwrap();
    let without_poll = candidates(&app, site).await;
    assert_eq!(poll(&app, key, *id, 2, true).await.0, StatusCode::OK);
    let after_fresh_poll = candidates(&app, site).await;
    app.finish().await;
    assert!(
        !after_presence.contains(id),
        "heartbeats must not renew work availability"
    );
    assert!(
        !after_replay.contains(id),
        "replaying an old poll must not renew availability"
    );
    assert!(
        !without_poll.contains(id),
        "legacy opt-in needs a new work poll"
    );
    assert!(after_fresh_poll.contains(id));
    assert_eq!(after_presence.len(), 2);
}

#[tokio::test]
async fn busy_website_agent_remains_eligible_only_while_its_lease_is_live() {
    let app = TestApp::new().await;
    let (site, snapshot) = saved_site(&app).await;
    let crew = crew(&app).await;
    let created = app
        .request(
            "POST",
            &format!("/internal/site-checks/{site}/review"),
            consent(&snapshot, &crew),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(created.0, StatusCode::OK);
    let (key, id) = &crew[0];
    let response = poll(&app, key, *id, 2, true).await;
    assert_eq!(response.0, StatusCode::OK);
    let reply: WorkReply = serde_json::from_value(response.1).unwrap();
    let lease = reply.assignment.unwrap().lease_id;
    sqlx::query("UPDATE devices SET work_polled_at = now() - interval '2 minutes' WHERE id = $1")
        .bind(id)
        .execute(&app.pool)
        .await
        .unwrap();
    assert!(candidates(&app, site).await.contains(id));
    sqlx::query("UPDATE work_leases SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(lease)
        .execute(&app.pool)
        .await
        .unwrap();
    assert!(!candidates(&app, site).await.contains(id));
    app.finish().await;
}

#[tokio::test]
async fn stale_work_poll_blocks_new_consent_and_payment_activation_until_fresh_poll() {
    let app = TestApp::new().await;
    let (site, snapshot) = saved_site(&app).await;
    let crew = crew(&app).await;
    let input = json!({"consent":consent(&snapshot, &crew), "price":{"asset":"nep141:fixture-usdc", "amount":"500000"}, "payment_expires_at":Utc::now().timestamp() + 300});
    let admit_path = format!("/internal/site-checks/{site}/admit-review");
    let reserved = app
        .request("POST", &admit_path, input.clone(), Some((app.owner, false)))
        .await;
    assert_eq!(reserved.0, StatusCode::OK);
    let fund_path = format!(
        "/internal/reviews/{}/fund",
        reserved.1["id"].as_str().unwrap()
    );
    let receipt = json!({"request_id":input["consent"]["request_id"], "invoice_id":Uuid::new_v4(), "price":input["price"]});
    let (key, id) = &crew[0];
    sqlx::query("UPDATE devices SET work_polled_at = now() - interval '2 minutes' WHERE id = $1")
        .bind(id)
        .execute(&app.pool)
        .await
        .unwrap();
    let mut next = input.clone();
    next["consent"]["request_id"] = json!(Uuid::new_v4());
    for (path, body) in [
        (
            format!("/internal/site-checks/{site}/review"),
            next["consent"].clone(),
        ),
        (admit_path, next),
        (fund_path.clone(), receipt.clone()),
    ] {
        let response = app
            .request("POST", &path, body, Some((app.owner, false)))
            .await;
        assert_eq!(response.0, StatusCode::CONFLICT, "{}", response.1);
        assert_eq!(response.1["error"], "selected_device_unavailable");
    }
    let counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM reviews WHERE state='awaiting_payment'), (SELECT count(*) FROM work_leases)")
        .fetch_one(&app.pool).await.unwrap();
    assert_eq!(counts, (1, 0));
    assert_eq!(poll(&app, key, *id, 2, true).await.0, StatusCode::OK);
    let funded = app
        .request("POST", &fund_path, receipt, Some((app.owner, false)))
        .await;
    assert_eq!(funded.0, StatusCode::OK, "{}", funded.1);
    assert_eq!(funded.1["state"], "queued");
    app.finish().await;
}
