use super::*;

fn admission(snapshot: &WebsiteSnapshot, crew: &[(DeviceKey, Uuid)]) -> Value {
    json!({"consent":consent(snapshot, crew), "price":{"asset":"nep141:fixture-usdc", "amount":"500000"}, "payment_expires_at":Utc::now().timestamp() + 300})
}

fn funding(admission: &Value) -> Value {
    json!({"request_id":admission["consent"]["request_id"], "invoice_id":Uuid::new_v4(), "price":admission["price"]})
}

async fn admit(app: &TestApp, site: Uuid, input: Value) -> Value {
    let response = app
        .request(
            "POST",
            &format!("/internal/site-checks/{site}/admit-review"),
            input,
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    response.1
}

#[tokio::test]
async fn no_agent_work_before_matching_funding_and_exact_retries_do_not_restart_work() {
    let app = TestApp::new().await;
    let (site, snapshot) = saved_site(&app).await;
    let crew = crew(&app).await;
    let input = admission(&snapshot, &crew);
    let (one, two) = tokio::join!(
        admit(&app, site, input.clone()),
        admit(&app, site, input.clone())
    );
    assert_eq!(one["id"], two["id"]);
    assert_eq!(one["state"], "awaiting_payment");
    assert_eq!(one["payment"]["price"], input["price"]);
    assert!(one["payment"]["invoice_id"].is_null());
    for (key, id) in &crew {
        let polled = poll(&app, key, *id, 2, true).await;
        assert_eq!(polled.0, StatusCode::OK, "{}", polled.1);
        assert!(polled.1["assignment"].is_null());
    }
    // A retry through the free pilot route cannot change the admitted price.
    assert_eq!(
        app.request(
            "POST",
            &format!("/internal/site-checks/{site}/review"),
            input["consent"].clone(),
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let id = one["id"].as_str().unwrap();
    let path = format!("/internal/reviews/{id}/fund");
    let receipt = funding(&input);
    assert_eq!(
        app.request("POST", &path, receipt.clone(), None).await.0,
        StatusCode::UNAUTHORIZED
    );
    for actor in [(Uuid::new_v4(), false), (app.admin, true)] {
        assert_eq!(
            app.request("POST", &path, receipt.clone(), Some(actor))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }
    for (field, value) in [
        ("request_id", json!(Uuid::new_v4())),
        ("price", json!({"asset":"nep141:other", "amount":"500000"})),
        (
            "price",
            json!({"asset":"nep141:fixture-usdc", "amount":"1"}),
        ),
    ] {
        let mut wrong = receipt.clone();
        wrong[field] = value;
        assert_eq!(
            app.request("POST", &path, wrong, Some((app.owner, false)))
                .await
                .0,
            StatusCode::CONFLICT
        );
    }
    let (funded, retry) = tokio::join!(
        app.request("POST", &path, receipt.clone(), Some((app.owner, false))),
        app.request("POST", &path, receipt.clone(), Some((app.owner, false)))
    );
    assert_eq!(funded.0, StatusCode::OK, "{}", funded.1);
    assert_eq!(funded, retry);
    assert_eq!(funded.1["state"], "queued");
    assert_eq!(funded.1["payment"]["invoice_id"], receipt["invoice_id"]);
    assert_eq!(
        funded.1["deadline_at"].as_i64().unwrap()
            - funded.1["payment"]["funded_at"].as_i64().unwrap(),
        35 * 60
    );
    for (index, (key, device)) in crew.iter().enumerate() {
        let assignment: WorkReply =
            serde_json::from_value(poll(&app, key, *device, 3, true).await.1).unwrap();
        let assignment = assignment.assignment.unwrap();
        assert_eq!(assignment.review_id.to_string(), id);
        let saved = evidence(&app, key, *device, assignment.lease_id).await;
        assert_eq!(saved.0, StatusCode::OK, "{}", saved.1);
        assert_eq!(saved.1["previous_reports"].as_array().unwrap().len(), index);
        let done = app
            .signed(
                key,
                &format!("/v1/devices/{device}/work/complete"),
                CompleteWork {
                    lease_id: assignment.lease_id,
                    result: WorkResult::Website(result(&snapshot)),
                },
            )
            .await;
        assert_eq!(done.0, StatusCode::OK, "{}", done.1);
        assert_eq!(done.1["evidence_complete"], true);
    }
    let retried = app
        .request("POST", &path, receipt, Some((app.owner, false)))
        .await;
    assert_eq!(retried.0, StatusCode::OK, "{}", retried.1);
    assert_eq!(retried.1["state"], "completed");
    assert_eq!(retried.1["deadline_at"], funded.1["deadline_at"]);
    assert_eq!(retried.1["payment"], funded.1["payment"]);
    assert!(poll(&app, &crew[0].0, crew[0].1, 4, true).await.1["assignment"].is_null());
    let steps: i64 = sqlx::query_scalar("SELECT count(*) FROM review_steps")
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert_eq!(steps, 3);
    app.finish().await;
}

#[tokio::test]
async fn admission_rejects_invalid_prices_and_changed_terms_without_staff_consent() {
    let app = TestApp::new().await;
    let (site, snapshot) = saved_site(&app).await;
    let crew = crew(&app).await;
    let input = admission(&snapshot, &crew);
    let path = format!("/internal/site-checks/{site}/admit-review");
    assert_eq!(
        app.request("POST", &path, input.clone(), None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.request("POST", &path, input.clone(), Some((app.admin, true)))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    for amount in ["0", "-1", "01", "0.5", "1e6", "9223372036854775808"] {
        let mut invalid = input.clone();
        invalid["price"]["amount"] = json!(amount);
        assert_eq!(
            app.request("POST", &path, invalid, Some((app.owner, false)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    for expires in [Utc::now().timestamp() - 1, Utc::now().timestamp() + 7200] {
        let mut invalid = input.clone();
        invalid["payment_expires_at"] = json!(expires);
        assert_eq!(
            app.request("POST", &path, invalid, Some((app.owner, false)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    let created = admit(&app, site, input.clone()).await;
    for (field, value) in [
        (
            "price",
            json!({"asset":"nep141:fixture-usdc", "amount":"500001"}),
        ),
        (
            "payment_expires_at",
            json!(input["payment_expires_at"].as_i64().unwrap() + 1),
        ),
    ] {
        let mut changed = input.clone();
        changed[field] = value;
        assert_eq!(
            app.request("POST", &path, changed, Some((app.owner, false)))
                .await
                .0,
            StatusCode::CONFLICT
        );
    }
    let mut changed = input.clone();
    changed["consent"]["device_ids"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    assert_eq!(
        app.request("POST", &path, changed, Some((app.owner, false)))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(admit(&app, site, input).await["id"], created["id"]);
    app.finish().await;
}

#[tokio::test]
async fn pending_payment_reserves_queue_capacity_and_cancel_or_expiry_releases_it() {
    let app = TestApp::new().await;
    let (site, snapshot) = saved_site(&app).await;
    let crew = crew(&app).await;
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(
            admit(&app, site, admission(&snapshot, &crew)).await["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let blocked = app
        .request(
            "POST",
            &format!("/internal/site-checks/{site}/admit-review"),
            admission(&snapshot, &crew),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(blocked.0, StatusCode::TOO_MANY_REQUESTS);
    let demo = json!({"request_id":Uuid::new_v4(), "scenario":"access_control_v1"});
    assert_eq!(
        app.request("POST", "/internal/reviews", demo, Some((app.owner, false)))
            .await
            .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    let cancelled = app
        .request(
            "POST",
            &format!("/internal/reviews/{}/cancel", ids[0]),
            json!({}),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(cancelled.0, StatusCode::OK, "{}", cancelled.1);
    assert_eq!(cancelled.1["state"], "cancelled");
    let replacement = admit(&app, site, admission(&snapshot, &crew)).await;
    assert_eq!(replacement["state"], "awaiting_payment");
    sqlx::query("UPDATE reviews SET deadline_at = now() - interval '1 second' WHERE id = $1")
        .bind(Uuid::parse_str(&ids[1]).unwrap())
        .execute(&app.pool)
        .await
        .unwrap();
    assert_eq!(
        admit(&app, site, admission(&snapshot, &crew)).await["state"],
        "awaiting_payment"
    );
    let expired = app
        .request(
            "GET",
            &format!("/internal/reviews/{}", ids[1]),
            json!({}),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(expired.1["state"], "failed");
    assert!(
        expired.1["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|step| step["state"] == "cancelled")
    );
    app.finish().await;
}

#[tokio::test]
async fn funding_rechecks_cancellation_expiry_approval_snapshot_and_retention() {
    for change in ["cancel", "expire", "revoke", "snapshot", "retention"] {
        let app = TestApp::new().await;
        let (site, snapshot) = saved_site(&app).await;
        let crew = crew(&app).await;
        let input = admission(&snapshot, &crew);
        let created = admit(&app, site, input.clone()).await;
        let id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();
        match change {
            "cancel" => {
                assert_eq!(
                    app.request(
                        "POST",
                        &format!("/internal/reviews/{id}/cancel"),
                        json!({}),
                        Some((app.owner, false))
                    )
                    .await
                    .0,
                    StatusCode::OK
                );
            }
            "expire" => {
                sqlx::query("UPDATE reviews SET deadline_at = now() - interval '1 second', payment_expires_at = now() - interval '1 second' WHERE id = $1").bind(id).execute(&app.pool).await.unwrap();
            }
            "revoke" => {
                assert_eq!(app.request("POST", &format!("/internal/devices/{}/decision", crew[0].1), json!({"action":"revoke_private", "reason":"Fixture operator no longer approved."}), Some((app.admin, true))).await.0, StatusCode::OK);
            }
            "snapshot" => {
                let mut changed = snapshot.clone();
                changed.homepage.text.push('!');
                sqlx::query("UPDATE site_checks SET snapshot = $2 WHERE id = $1")
                    .bind(site)
                    .bind(DbJson(changed))
                    .execute(&app.pool)
                    .await
                    .unwrap();
            }
            "retention" => {
                sqlx::query("UPDATE site_checks SET evidence_expires_at = now() + interval '1 minute' WHERE id = $1").bind(site).execute(&app.pool).await.unwrap();
            }
            _ => unreachable!(),
        }
        let rejected = app
            .request(
                "POST",
                &format!("/internal/reviews/{id}/fund"),
                funding(&input),
                Some((app.owner, false)),
            )
            .await;
        assert_eq!(rejected.0, StatusCode::CONFLICT, "{change}: {}", rejected.1);
        let invoice: Option<Uuid> =
            sqlx::query_scalar("SELECT funded_invoice_id FROM reviews WHERE id = $1")
                .bind(id)
                .fetch_one(&app.pool)
                .await
                .unwrap();
        assert!(invoice.is_none());
        for (key, device) in &crew {
            assert!(poll(&app, key, *device, 2, true).await.1["assignment"].is_null());
        }
        app.finish().await;
    }
}

#[tokio::test]
async fn a_settled_invoice_cannot_fund_two_reviews_or_revive_a_cancelled_one() {
    let app = TestApp::new().await;
    let (site, snapshot) = saved_site(&app).await;
    let crew = crew(&app).await;
    let first = admission(&snapshot, &crew);
    let second = admission(&snapshot, &crew);
    let one = admit(&app, site, first.clone()).await;
    let two = admit(&app, site, second.clone()).await;
    let receipt = funding(&first);
    let one_path = format!("/internal/reviews/{}/fund", one["id"].as_str().unwrap());
    assert_eq!(
        app.request("POST", &one_path, receipt.clone(), Some((app.owner, false)))
            .await
            .0,
        StatusCode::OK
    );
    let mut reused = funding(&second);
    reused["invoice_id"] = receipt["invoice_id"].clone();
    let rejected = app
        .request(
            "POST",
            &format!("/internal/reviews/{}/fund", two["id"].as_str().unwrap()),
            reused,
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(rejected.0, StatusCode::CONFLICT);
    assert_eq!(rejected.1["error"], "invoice_already_used");
    assert_eq!(
        app.request("POST", &one_path, funding(&first), Some((app.owner, false)))
            .await
            .0,
        StatusCode::CONFLICT
    );
    let cancelled = app
        .request(
            "POST",
            &format!("/internal/reviews/{}/cancel", one["id"].as_str().unwrap()),
            json!({}),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(cancelled.1["state"], "cancelled");
    let retried = app
        .request("POST", &one_path, receipt, Some((app.owner, false)))
        .await;
    assert_eq!(retried.0, StatusCode::OK, "{}", retried.1);
    assert_eq!(retried.1["state"], "cancelled");
    assert_eq!(retried.1["payment"], cancelled.1["payment"]);
    assert!(poll(&app, &crew[0].0, crew[0].1, 2, true).await.1["assignment"].is_null());
    app.finish().await;
}

#[tokio::test]
async fn temporarily_unavailable_selected_agents_cannot_be_replaced_by_payment() {
    let app = TestApp::new().await;
    let (site, snapshot) = saved_site(&app).await;
    let crew = crew(&app).await;
    let input = admission(&snapshot, &crew);
    let created = admit(&app, site, input.clone()).await;
    let path = format!("/internal/reviews/{}/fund", created["id"].as_str().unwrap());
    let receipt = funding(&input);
    for change in ["paused", "offline", "opted_out"] {
        match change {
            "paused" => {
                sqlx::query("UPDATE devices SET paused = true WHERE id = $1")
                    .bind(crew[0].1)
                    .execute(&app.pool)
                    .await
                    .unwrap();
            }
            "offline" => {
                sqlx::query(
                    "UPDATE devices SET last_seen_at = now() - interval '31 seconds' WHERE id = $1",
                )
                .bind(crew[0].1)
                .execute(&app.pool)
                .await
                .unwrap();
            }
            "opted_out" => {
                sqlx::query("UPDATE devices SET website_reviews = false WHERE id = $1")
                    .bind(crew[0].1)
                    .execute(&app.pool)
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let rejected = app
            .request("POST", &path, receipt.clone(), Some((app.owner, false)))
            .await;
        assert_eq!(rejected.0, StatusCode::CONFLICT, "{change}: {}", rejected.1);
        assert_eq!(rejected.1["error"], "selected_device_unavailable");
        sqlx::query("UPDATE devices SET paused = false, last_seen_at = now(), website_reviews = true WHERE id = $1").bind(crew[0].1).execute(&app.pool).await.unwrap();
    }
    let funded = app
        .request("POST", &path, receipt, Some((app.owner, false)))
        .await;
    assert_eq!(funded.0, StatusCode::OK, "{}", funded.1);
    assert_eq!(funded.1["website"], created["website"]);
    assert_eq!(funded.1["state"], "queued");
    app.finish().await;
}

#[tokio::test]
async fn concurrent_cancellation_and_funding_never_revive_cancelled_work() {
    let app = TestApp::new().await;
    let (site, snapshot) = saved_site(&app).await;
    let crew = crew(&app).await;
    let input = admission(&snapshot, &crew);
    let created = admit(&app, site, input.clone()).await;
    let id = created["id"].as_str().unwrap();
    let receipt = funding(&input);
    let fund = format!("/internal/reviews/{id}/fund");
    let cancel = format!("/internal/reviews/{id}/cancel");
    let (funded, cancelled) = tokio::join!(
        app.request("POST", &fund, receipt.clone(), Some((app.owner, false))),
        app.request("POST", &cancel, json!({}), Some((app.owner, false)))
    );
    assert_eq!(cancelled.0, StatusCode::OK, "{}", cancelled.1);
    let final_state = app
        .request(
            "GET",
            &format!("/internal/reviews/{id}"),
            json!({}),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(final_state.1["state"], "cancelled");
    let retry = app
        .request("POST", &fund, receipt.clone(), Some((app.owner, false)))
        .await;
    if funded.0 == StatusCode::OK {
        assert_eq!(
            final_state.1["payment"]["invoice_id"],
            receipt["invoice_id"]
        );
        assert_eq!(retry.0, StatusCode::OK, "{}", retry.1);
        assert_eq!(retry.1["state"], "cancelled");
    } else {
        assert_eq!(funded.0, StatusCode::CONFLICT, "{}", funded.1);
        assert!(final_state.1["payment"]["invoice_id"].is_null());
        assert_eq!(retry.0, StatusCode::CONFLICT);
    }
    assert!(poll(&app, &crew[0].0, crew[0].1, 2, true).await.1["assignment"].is_null());
    app.finish().await;
}

#[tokio::test]
async fn paid_cpu_budget_covers_retention_and_survives_configuration_changes() {
    let mut app = TestApp::with_budget(3600).await;
    let (site, snapshot) = saved_site(&app).await;
    let crew = crew(&app).await;
    let plan = app
        .request(
            "GET",
            &format!("/internal/site-checks/{site}/review-plan"),
            json!({}),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(plan.1["review_timeout_seconds"], 11100);
    let input = admission(&snapshot, &crew);
    sqlx::query(
        "UPDATE site_checks SET evidence_expires_at=now()+interval '40 minutes' WHERE id=$1",
    )
    .bind(site)
    .execute(&app.pool)
    .await
    .unwrap();
    assert_eq!(
        app.request(
            "POST",
            &format!("/internal/site-checks/{site}/admit-review"),
            input.clone(),
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    sqlx::query("UPDATE site_checks SET evidence_expires_at=now()+interval '7 days' WHERE id=$1")
        .bind(site)
        .execute(&app.pool)
        .await
        .unwrap();
    let saved = admit(&app, site, input.clone()).await;
    app.change_budget(600);
    let path = format!("/internal/reviews/{}/fund", saved["id"].as_str().unwrap());
    let receipt = funding(&input);
    let funded = app
        .request("POST", &path, receipt.clone(), Some((app.owner, false)))
        .await;
    assert_eq!(funded.0, StatusCode::OK, "{}", funded.1);
    assert_eq!(
        funded.1["deadline_at"].as_i64().unwrap()
            - funded.1["payment"]["funded_at"].as_i64().unwrap(),
        11100
    );
    let retry = app
        .request("POST", &path, receipt, Some((app.owner, false)))
        .await;
    assert_eq!(funded, retry);
    let work: WorkReply =
        serde_json::from_value(poll(&app, &crew[0].0, crew[0].1, 2, true).await.1).unwrap();
    let duration: i64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM deadline_at - created_at)::bigint FROM work_leases WHERE id=$1",
    )
    .bind(work.assignment.unwrap().lease_id)
    .fetch_one(&app.pool)
    .await
    .unwrap();
    assert_eq!(duration, 3600);
    app.finish().await;
}
