use super::*;
use patchriot_protocol::{sources::*, website_reviews::*};

fn upload() -> Value {
    json!({"request_id":Uuid::new_v4(),"title":"Owned access example","objective":"Check who can read a record.","permission_note":"I wrote this synthetic code and authorize its review.","accepts_private_storage":true,"files":[{"path":"access.py","text":"def read(user, owner, data):\n    return data\n"}]})
}
async fn saved(app: &TestApp) -> (Uuid, SourceBundle) {
    let (status, body) = app
        .request(
            "POST",
            "/internal/sources",
            upload(),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = serde_json::from_value(body["id"].clone()).unwrap();
    assert_eq!(
        app.request(
            "POST",
            &format!("/internal/sources/{id}/decision"),
            json!({"approve":true,"note":"Verified ownership of this synthetic example."}),
            Some((app.admin, true))
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, bundle) = app
        .request(
            "GET",
            &format!("/internal/sources/{id}/evidence"),
            json!({}),
            Some((app.owner, false)),
        )
        .await;
    (id, serde_json::from_value(bundle).unwrap())
}
async fn poll(
    app: &TestApp,
    key: &DeviceKey,
    id: Uuid,
    sequence: u64,
    source_reviews: bool,
) -> (StatusCode, Value) {
    app.signed(
        key,
        &format!("/v1/devices/{id}/work/poll"),
        WorkPoll {
            sequence,
            website_reviews: true,
            source_reviews,
            live_tests: false,
            live_tools: vec![],
        },
    )
    .await
}
async fn crew(app: &TestApp) -> Vec<(DeviceKey, Uuid)> {
    let mut devices = vec![];
    for seed in [121, 122, 123] {
        let key = DeviceKey::from_bytes(&[seed; 32]);
        let id = app.agent(&key, app.owner).await;
        assert_eq!(
            app.request(
                "POST",
                &format!("/internal/devices/{id}/decision"),
                json!({"action":"approve_private","capabilities":TestApp::checked_capabilities(),"reason":"Reviewed this synthetic operator."}),
                Some((app.admin, true))
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(poll(app, &key, id, 1, true).await.0, StatusCode::OK);
        devices.push((key, id));
    }
    devices
}
fn consent(bundle: &SourceBundle, devices: &[(DeviceKey, Uuid)]) -> Value {
    json!({"request_id":Uuid::new_v4(),"snapshot_sha256":bundle_hash(bundle).unwrap(),"device_ids":devices.iter().map(|(_,id)|id).collect::<Vec<_>>(),"accepts_operator_access":true})
}
fn result(bundle: &SourceBundle) -> SourceAgentResult {
    serde_json::from_value(json!({"kind":"source_agent_v1","execution":{"state":"completed","declared_model":"test-local-model","model":"test-local-model","model_digest":"a".repeat(64),"image_digest":format!("sha256:{}","b".repeat(64)),"duration_ms":1000,"inference_calls":1,"terminal_calls":1,"cleanup_confirmed":true},"snapshot_sha256":bundle_hash(bundle).unwrap(),"inspected_snapshot_sha256":bundle_hash(bundle).unwrap(),"assessment":{"summary":"A return does not check the owner.","findings":[{"title":"Missing ownership check","support":"observed_in_snapshot","explanation":"The supplied function returns data without checking the caller.","suggested_action":"Check caller ownership and test it.","citations":[{"resource_sha256":bundle.files[0].sha256,"quote":"return data"}]}],"limitations":["Static review only; no target code was executed."]},"raw_summary":""})).unwrap()
}

#[tokio::test]
async fn source_intake_is_private_immutable_bounded_and_owner_deletable() {
    let app = TestApp::new().await;
    let input = upload();
    assert_eq!(
        app.request("POST", "/internal/sources", input.clone(), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, body) = app
        .request(
            "POST",
            "/internal/sources",
            input.clone(),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let id = body["id"].as_str().unwrap();
    assert_eq!(body["state"], "pending_approval");
    assert!(!body.to_string().contains("return data"));
    assert_eq!(
        app.request(
            "POST",
            "/internal/sources",
            input.clone(),
            Some((app.owner, false))
        )
        .await
        .1["id"],
        body["id"]
    );
    let mut changed = input.clone();
    changed["objective"] = json!("Different scope");
    assert_eq!(
        app.request(
            "POST",
            "/internal/sources",
            changed,
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let other = Some((Uuid::new_v4(), false));
    for path in [
        format!("/internal/sources/{id}"),
        format!("/internal/sources/{id}/evidence"),
        format!("/internal/sources/{id}/review-plan"),
    ] {
        assert_eq!(
            app.request("GET", &path, json!({}), other).await.0,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        app.request("GET", "/internal/sources", json!({}), other)
            .await
            .1,
        json!([])
    );
    assert_eq!(
        app.request(
            "GET",
            &format!("/internal/sources/{id}/review-plan"),
            json!({}),
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let decision = json!({"approve":true,"note":"Reviewed exact supplied source and ownership."});
    assert_eq!(
        app.request(
            "POST",
            &format!("/internal/sources/{id}/decision"),
            decision.clone(),
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.request(
            "POST",
            &format!("/internal/sources/{id}/decision"),
            decision,
            Some((app.admin, true))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        app.request(
            "POST",
            &format!("/internal/sources/{id}/delete"),
            json!({}),
            Some((app.admin, true))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.request(
            "POST",
            &format!("/internal/sources/{id}/delete"),
            json!({}),
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        app.request(
            "GET",
            &format!("/internal/sources/{id}/evidence"),
            json!({}),
            Some((app.owner, false))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.request("POST", "/internal/sources", input, Some((app.owner, false)))
            .await
            .1["state"],
        "deleted",
        "retry cannot restore source bytes"
    );
    let empty: bool = sqlx::query_scalar("SELECT bundle IS NULL FROM source_uploads WHERE id=$1")
        .bind(Uuid::parse_str(id).unwrap())
        .fetch_one(&app.pool)
        .await
        .unwrap();
    assert!(empty);
    for path in ["../access.py", "test.zip", ".env", "secrets.json"] {
        let mut bad = upload();
        bad["files"][0]["path"] = json!(path);
        assert_eq!(
            app.request("POST", "/internal/sources", bad, Some((app.owner, false)))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    app.finish().await;
}

#[tokio::test]
async fn source_jobs_need_separate_opt_in_and_exact_consent_then_deliver_three_real_role_records() {
    let app = TestApp::new().await;
    let (id, bundle) = saved(&app).await;
    let devices = crew(&app).await;
    let input = consent(&bundle, &devices);
    let path = format!("/internal/sources/{id}/review");
    assert_eq!(
        app.request("POST", &path, input.clone(), Some((app.admin, true)))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        poll(&app, &devices[0].0, devices[0].1, 2, false).await.0,
        StatusCode::OK
    );
    let plan = app
        .request(
            "GET",
            &format!("/internal/sources/{id}/review-plan"),
            json!({}),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(plan.1["recommended_device_ids"], json!([]));
    assert_eq!(
        app.request("POST", &path, input.clone(), Some((app.owner, false)))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        poll(&app, &devices[0].0, devices[0].1, 2, true).await.0,
        StatusCode::CONFLICT,
        "opt-in cannot change on a replay"
    );
    assert_eq!(
        poll(&app, &devices[0].0, devices[0].1, 3, true).await.0,
        StatusCode::OK
    );
    let (status, review) = app
        .request("POST", &path, input.clone(), Some((app.owner, false)))
        .await;
    assert_eq!(status, StatusCode::OK, "{review}");
    assert!(review["website"].is_null());
    assert_eq!(review["mode"], "source_agent");
    assert_eq!(
        app.request("POST", &path, input.clone(), Some((app.owner, false)))
            .await
            .1["id"],
        review["id"]
    );
    for (index, (key, device)) in devices.iter().enumerate() {
        let (_, work) = poll(&app, key, *device, 4, true).await;
        let lease: Uuid = serde_json::from_value(work["assignment"]["lease_id"].clone()).unwrap();
        assert_eq!(work["assignment"]["source"]["source_id"], id.to_string());
        assert!(work["assignment"]["website"].is_null());
        let evidence_path = format!("/v1/devices/{device}/work/source-evidence");
        let evidence = app
            .signed(
                key,
                &evidence_path,
                ReadWorkEvidence {
                    nonce: Uuid::new_v4(),
                    lease_id: lease,
                },
            )
            .await;
        assert_eq!(evidence.0, StatusCode::OK, "{}", evidence.1);
        assert_eq!(
            evidence.1["previous_reports"].as_array().unwrap().len(),
            index
        );
        let wrong = app
            .signed(
                &devices[(index + 1) % 3].0,
                &evidence_path,
                ReadWorkEvidence {
                    nonce: Uuid::new_v4(),
                    lease_id: lease,
                },
            )
            .await;
        assert_eq!(wrong.0, StatusCode::UNAUTHORIZED);
        assert_ne!(
            app.signed(
                key,
                &format!("/v1/devices/{device}/work/evidence"),
                ReadWorkEvidence {
                    nonce: Uuid::new_v4(),
                    lease_id: lease
                }
            )
            .await
            .0,
            StatusCode::OK
        );
        let mut result = result(&bundle);
        if index == 1 {
            result.assessment.as_mut().unwrap().findings[0].citations[0].quote =
                "invented quote".into();
        }
        let response = app
            .signed(
                key,
                &format!("/v1/devices/{device}/work/complete"),
                CompleteWork {
                    lease_id: lease,
                    result: WorkResult::Source(result),
                },
            )
            .await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        assert_eq!(response.1["evidence_complete"], index != 1);
    }
    let final_review = app
        .request(
            "GET",
            &format!("/internal/reviews/{}", review["id"].as_str().unwrap()),
            json!({}),
            Some((app.owner, false)),
        )
        .await
        .1;
    assert_eq!(
        final_review["state"], "needs_review",
        "fabricated citation cannot be a complete report"
    );
    app.finish().await;
}

#[tokio::test]
async fn deleting_or_expiring_source_fences_reads_and_funding() {
    for delete in [true, false] {
        let app = TestApp::new().await;
        let (id, bundle) = saved(&app).await;
        let devices = crew(&app).await;
        let input = consent(&bundle, &devices);
        let response=app.request("POST",&format!("/internal/sources/{id}/admit-review"),json!({"consent":input,"price":{"asset":"nep141:fixture.near","amount":"10000000"},"payment_expires_at":Utc::now().timestamp()+600}),Some((app.owner,false))).await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        let review = response.1["id"].as_str().unwrap();
        assert!(poll(&app, &devices[0].0, devices[0].1, 2, true).await.1["assignment"].is_null());
        if delete {
            assert_eq!(
                app.request(
                    "POST",
                    &format!("/internal/sources/{id}/delete"),
                    json!({}),
                    Some((app.owner, false))
                )
                .await
                .0,
                StatusCode::OK
            );
        } else {
            sqlx::query(
                "UPDATE source_uploads SET expires_at=now()-interval '1 second' WHERE id=$1",
            )
            .bind(id)
            .execute(&app.pool)
            .await
            .unwrap();
        }
        assert_eq!(app.request("POST",&format!("/internal/reviews/{review}/fund"),json!({"request_id":input["request_id"],"invoice_id":Uuid::new_v4(),"price":{"asset":"nep141:fixture.near","amount":"10000000"}}),Some((app.owner,false))).await.0,StatusCode::CONFLICT);
        assert_eq!(
            app.request(
                "GET",
                &format!("/internal/sources/{id}/evidence"),
                json!({}),
                Some((app.owner, false))
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        let bytes: bool =
            sqlx::query_scalar("SELECT bundle IS NULL FROM source_uploads WHERE id=$1")
                .bind(id)
                .fetch_one(&app.pool)
                .await
                .unwrap();
        assert!(bytes);
        app.finish().await;
    }
}

#[tokio::test]
async fn active_source_work_loses_reads_renewal_and_completion_on_delete_expiry_or_revocation() {
    for stop in ["delete", "expire", "revoke"] {
        let app = TestApp::new().await;
        let (id, bundle) = saved(&app).await;
        let devices = crew(&app).await;
        let input = consent(&bundle, &devices);
        let response = app
            .request(
                "POST",
                &format!("/internal/sources/{id}/review"),
                input,
                Some((app.owner, false)),
            )
            .await;
        assert_eq!(response.0, StatusCode::OK, "{}", response.1);
        let (key, device) = &devices[0];
        let (_, work) = poll(&app, key, *device, 2, true).await;
        let lease: Uuid = serde_json::from_value(work["assignment"]["lease_id"].clone()).unwrap();
        assert_eq!(app.renew(key, *device, lease, 1).await.0, StatusCode::OK);
        match stop {
            "delete" => {
                assert_eq!(
                    app.request(
                        "POST",
                        &format!("/internal/sources/{id}/delete"),
                        json!({}),
                        Some((app.owner, false))
                    )
                    .await
                    .0,
                    StatusCode::OK
                );
            }
            "expire" => {
                sqlx::query(
                    "UPDATE source_uploads SET expires_at=now()-interval '1 second' WHERE id=$1",
                )
                .bind(id)
                .execute(&app.pool)
                .await
                .unwrap();
            }
            _ => {
                assert_eq!(app.request("POST",&format!("/internal/devices/{device}/decision"),json!({"action":"revoke_private","reason":"Stop this private source review."}),Some((app.admin,true))).await.0,StatusCode::OK);
            }
        }
        assert_ne!(
            app.signed(
                key,
                &format!("/v1/devices/{device}/work/source-evidence"),
                ReadWorkEvidence {
                    nonce: Uuid::new_v4(),
                    lease_id: lease
                }
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_ne!(app.renew(key, *device, lease, 2).await.0, StatusCode::OK);
        assert_ne!(
            app.signed(
                key,
                &format!("/v1/devices/{device}/work/complete"),
                CompleteWork {
                    lease_id: lease,
                    result: WorkResult::Source(result(&bundle))
                }
            )
            .await
            .0,
            StatusCode::OK
        );
        assert!(poll(&app, &devices[1].0, devices[1].1, 2, true).await.1["assignment"].is_null());
        app.finish().await;
    }
}

#[tokio::test]
async fn paid_source_activation_is_exactly_once_and_replay_cannot_revive_cancelled_work() {
    let app = TestApp::new().await;
    let (id, bundle) = saved(&app).await;
    let devices = crew(&app).await;
    let input = consent(&bundle, &devices);
    let price = json!({"asset":"nep141:fixture.near","amount":"10000000"});
    let response = app
        .request(
            "POST",
            &format!("/internal/sources/{id}/admit-review"),
            json!({"consent":input,"price":price,"payment_expires_at":Utc::now().timestamp()+600}),
            Some((app.owner, false)),
        )
        .await;
    assert_eq!(response.0, StatusCode::OK, "{}", response.1);
    let review = response.1["id"].as_str().unwrap();
    assert!(poll(&app, &devices[0].0, devices[0].1, 2, true).await.1["assignment"].is_null());
    let event = json!({"request_id":input["request_id"],"invoice_id":Uuid::new_v4(),"price":price});
    let path = format!("/internal/reviews/{review}/fund");
    let (first, second) = tokio::join!(
        app.request("POST", &path, event.clone(), Some((app.owner, false))),
        app.request("POST", &path, event.clone(), Some((app.owner, false)))
    );
    assert_eq!(first.0, StatusCode::OK, "{}", first.1);
    assert_eq!(second.0, StatusCode::OK, "{}", second.1);
    assert_eq!(
        first.1["payment"]["funded_invoice_id"],
        second.1["payment"]["funded_invoice_id"]
    );
    assert!(!poll(&app, &devices[0].0, devices[0].1, 3, true).await.1["assignment"].is_null());
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
        app.request("POST", &path, event, Some((app.owner, false)))
            .await
            .1["state"],
        "cancelled"
    );
    assert!(poll(&app, &devices[1].0, devices[1].1, 2, true).await.1["assignment"].is_null());
    app.finish().await;
}
