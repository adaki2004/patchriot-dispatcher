//! A bounded queue for owned examples and explicitly shared website snapshots.
//! Website roles are pinned to the consented devices. Leases fence late results.

use crate::{Actor, ApiError, AppState, actor, now, verify};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, Utc};
use patchriot_protocol::*;
use sqlx::{FromRow, PgPool, Postgres, Transaction, types::Json as DbJson};
use uuid::Uuid;

pub(crate) mod funding;
pub(crate) mod pentests;
pub(crate) mod sources;
pub(crate) mod websites;

type Tx<'a> = Transaction<'a, Postgres>;

// A single short database lock keeps the prototype's queue/compute reservations
// consistent across HTTP requests. Never hold this lock across network or work.
pub(crate) async fn scheduler(tx: &mut Tx<'_>) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock(72638102)")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(crate) async fn sweep(tx: &mut Tx<'_>) -> Result<(), ApiError> {
    crate::sources::sweep(tx).await?;
    sqlx::query("UPDATE reviews r SET state='failed' WHERE r.mode='pentest_agent' AND r.state IN ('awaiting_payment','queued','running') AND r.pentest_context->'scope'->>'authentication' IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pentest_credentials c WHERE c.pentest_id=r.pentest_id AND c.expires_at>now())").execute(&mut **tx).await?;
    sqlx::query("UPDATE reviews r SET state = 'failed' WHERE r.mode = 'pentest_agent' AND r.state IN ('queued','running') AND (EXISTS (SELECT 1 FROM review_steps s JOIN devices d ON d.id = s.assigned_device_id WHERE s.review_id = r.id AND (d.approval <> 'approved' OR NOT d.private_work_approved)) OR NOT EXISTS (SELECT 1 FROM pentests p WHERE p.id = r.pentest_id AND p.state = 'approved' AND p.ownership_verified_at IS NOT NULL AND p.expires_at > now()))")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE reviews r SET state = 'failed' WHERE r.mode = 'source_agent' AND r.state IN ('awaiting_payment','queued','running') AND (EXISTS (SELECT 1 FROM review_steps s JOIN devices d ON d.id = s.assigned_device_id WHERE s.review_id = r.id AND (d.approval <> 'approved' OR NOT d.private_work_approved)) OR NOT EXISTS (SELECT 1 FROM source_uploads u WHERE u.id = r.source_id AND u.state = 'approved' AND u.bundle IS NOT NULL AND u.expires_at > now()))")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE reviews r SET state = 'failed' WHERE r.mode = 'website_agent' AND r.state IN ('awaiting_payment','queued','running') AND (EXISTS (SELECT 1 FROM review_steps s JOIN devices d ON d.id = s.assigned_device_id WHERE s.review_id = r.id AND (d.approval <> 'approved' OR NOT d.private_work_approved)) OR NOT EXISTS (SELECT 1 FROM site_checks w WHERE w.id = r.site_check_id AND w.snapshot IS NOT NULL AND w.evidence_expires_at > now()))")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE work_leases l SET state = 'expired' FROM review_steps s, reviews r, devices d WHERE l.state = 'active' AND s.id = l.step_id AND r.id = s.review_id AND d.id = l.device_id AND (l.expires_at <= now() OR l.deadline_at <= now() OR r.deadline_at <= now() OR d.approval <> 'approved')")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE review_steps s SET state = CASE WHEN attempts < (CASE WHEN r.mode = 'pentest_agent' THEN 1 ELSE 3 END) THEN 'queued' ELSE 'failed' END FROM work_leases l, reviews r WHERE s.current_lease_id = l.id AND r.id = s.review_id AND s.state = 'leased' AND l.state = 'expired'")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE reviews r SET state = 'failed' WHERE r.state IN ('awaiting_payment','queued','running') AND (r.deadline_at <= now() OR EXISTS (SELECT 1 FROM review_steps s WHERE s.review_id = r.id AND s.state = 'failed'))")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE work_leases l SET state = 'cancelled' FROM review_steps s, reviews r WHERE s.id = l.step_id AND r.id = s.review_id AND r.state IN ('failed','cancelled') AND l.state = 'active'")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE review_steps s SET state = 'cancelled' FROM reviews r WHERE s.review_id = r.id AND r.state IN ('failed','cancelled') AND s.state IN ('queued','leased')")
        .execute(&mut **tx).await?;
    crate::credentials::sweep(tx).await?;
    Ok(())
}

pub(crate) async fn expire(pool: &PgPool) -> Result<(), ApiError> {
    let mut tx = pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    tx.commit().await?;
    Ok(())
}

#[derive(FromRow)]
struct ReviewRow {
    id: Uuid,
    request_id: Uuid,
    state: String,
    mode: String,
    scenario: String,
    website_context: Option<DbJson<patchriot_protocol::website_reviews::WebsiteReviewContext>>,
    source_context: Option<DbJson<patchriot_protocol::sources::SourceReviewContext>>,
    pentest_context: Option<DbJson<patchriot_protocol::pentests::PentestContext>>,
    payment_terms: Option<DbJson<patchriot_protocol::website_reviews::ReviewPrice>>,
    payment_expires_at: Option<DateTime<Utc>>,
    funded_invoice_id: Option<Uuid>,
    funded_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    deadline_at: DateTime<Utc>,
    agent_attempt_seconds: i32,
}

#[derive(FromRow)]
struct StepRow {
    review_id: Uuid,
    role: String,
    state: String,
    attempts: i32,
    device_id: Option<Uuid>,
    operator_id: Option<Uuid>,
    compute_group: Option<String>,
    result: Option<DbJson<WorkResult>>,
    fixture_matches: Option<bool>,
    evidence_complete: Option<bool>,
    live_progress: Option<DbJson<patchriot_protocol::pentests::LiveProgressView>>,
}

fn role(value: &str) -> Result<ReviewRole, ApiError> {
    Ok(serde_json::from_value(serde_json::Value::String(
        value.into(),
    ))?)
}

async fn views(
    pool: &PgPool,
    caller: &Actor,
    id: Option<Uuid>,
) -> Result<Vec<ReviewView>, ApiError> {
    let reviews = sqlx::query_as::<_, ReviewRow>("SELECT id, request_id, state, mode, scenario, website_context, source_context, pentest_context, payment_terms, payment_expires_at, funded_invoice_id, funded_at, created_at, deadline_at, agent_attempt_seconds FROM reviews WHERE (requester_id = $1 OR $2) AND ($3::uuid IS NULL OR id = $3) ORDER BY created_at DESC LIMIT 50")
        .bind(caller.id).bind(caller.admin).bind(id).fetch_all(pool).await?;
    let ids: Vec<_> = reviews.iter().map(|r| r.id).collect();
    let steps = sqlx::query_as::<_, StepRow>("SELECT s.review_id, s.role, s.state, s.attempts, l.device_id, l.operator_id, l.compute_group, CASE WHEN $2 THEN s.result ELSE NULL END AS result, s.fixture_matches, s.evidence_complete, l.live_progress FROM review_steps s LEFT JOIN work_leases l ON l.id = s.current_lease_id WHERE s.review_id = ANY($1) ORDER BY s.position")
        .bind(&ids).bind(id.is_some()).fetch_all(pool).await?;
    let mut result = Vec::new();
    for review in reviews {
        let mut parts = Vec::new();
        for step in steps.iter().filter(|s| s.review_id == review.id) {
            parts.push(ReviewStepView {
                role: role(&step.role)?,
                state: step.state.clone(),
                attempts: step.attempts,
                device_id: step.device_id,
                operator_id: step.operator_id,
                compute_group: step.compute_group.clone(),
                result: step.result.as_ref().map(|r| r.0.clone()),
                fixture_matches: step.fixture_matches,
                evidence_complete: step.evidence_complete,
                progress: step.live_progress.as_ref().map(|p| p.0.clone()),
            });
        }
        result.push(ReviewView {
            id: review.id,
            request_id: review.request_id,
            scenario: serde_json::from_value(serde_json::Value::String(review.scenario))?,
            evidence_source: if review.mode == "pentest_agent" {
                "operator_reported_live_http_evidence_not_a_safety_verdict".into()
            } else if review.mode == "source_agent" {
                "operator_reported_static_source_review_not_a_safety_verdict".into()
            } else if review.mode == "website_agent" {
                "operator_reported_static_website_review_not_a_safety_verdict".into()
            } else if review.mode == "owned_agent" {
                "agent_reported_owned_example_not_independently_verified".into()
            } else {
                "device_reported_fixture_not_independently_verified".into()
            },
            mode: review.mode,
            state: review.state,
            created_at: review.created_at.timestamp(),
            deadline_at: review.deadline_at.timestamp(),
            steps: parts,
            website: review.website_context.map(|context| context.0),
            source: review.source_context.map(|context| context.0),
            pentest: review.pentest_context.map(|context| context.0),
            payment: review
                .payment_terms
                .zip(review.payment_expires_at)
                .map(
                    |(price, expires)| patchriot_protocol::website_reviews::ReviewPayment {
                        price: price.0,
                        expires_at: expires.timestamp(),
                        invoice_id: review.funded_invoice_id,
                        funded_at: review.funded_at.map(|time| time.timestamp()),
                    },
                ),
        });
    }
    Ok(result)
}

async fn view(pool: &PgPool, caller: &Actor, id: Uuid) -> Result<ReviewView, ApiError> {
    views(pool, caller, Some(id))
        .await?
        .pop()
        .ok_or_else(ApiError::missing)
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateReview>,
) -> Result<Json<ReviewView>, ApiError> {
    let caller = actor(&headers, &state)?;
    if matches!(
        input.mode,
        ReviewMode::WebsiteAgent | ReviewMode::SourceAgent | ReviewMode::PentestAgent
    ) || input.scenario != FixtureScenario::AccessControlV1
    {
        return Err(ApiError::bad("website_review_requires_separate_consent"));
    }
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    let existing: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, mode FROM reviews WHERE requester_id = $1 AND request_id = $2")
            .bind(caller.id)
            .bind(input.request_id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some((id, mode)) = existing {
        if mode != input.mode.as_str() {
            return Err(ApiError::conflict("conflicting_review_request"));
        }
        tx.commit().await?;
        return Ok(Json(view(&state.pool, &caller, id).await?));
    }
    let (total, own): (i64, i64) = sqlx::query_as("SELECT count(*), count(*) FILTER (WHERE requester_id = $1) FROM reviews WHERE state IN ('awaiting_payment','queued','running')")
        .bind(caller.id).fetch_one(&mut *tx).await?;
    if total >= 30 || own >= 3 {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "fixture_queue_full",
        ));
    }
    let id = Uuid::new_v4();
    // Three sequential roles plus five minutes for waiting. Save this limit;
    // later configuration changes and lease renewal cannot extend the review.
    let seconds = if input.mode == ReviewMode::OwnedAgent {
        state.agent_review_seconds()
    } else {
        900
    };
    sqlx::query("INSERT INTO reviews (id, requester_id, request_id, scenario, mode, deadline_at, agent_attempt_seconds) VALUES ($1,$2,$3,'access_control_v1',$4,now() + make_interval(secs => $5),$6)")
        .bind(id).bind(caller.id).bind(input.request_id).bind(input.mode.as_str()).bind(seconds as f64).bind(state.agent_attempt_seconds as i32).execute(&mut *tx).await?;
    for (position, role) in [
        ReviewRole::Investigator,
        ReviewRole::Reproducer,
        ReviewRole::Challenger,
    ]
    .into_iter()
    .enumerate()
    {
        sqlx::query(
            "INSERT INTO review_steps (id, review_id, role, position) VALUES ($1,$2,$3,$4)",
        )
        .bind(Uuid::new_v4())
        .bind(id)
        .bind(role.as_str())
        .bind(position as i16)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(Json(view(&state.pool, &caller, id).await?))
}

pub async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ReviewView>>, ApiError> {
    let caller = actor(&headers, &state)?;
    expire(&state.pool).await?;
    Ok(Json(views(&state.pool, &caller, None).await?))
}

pub async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<ReviewView>, ApiError> {
    let caller = actor(&headers, &state)?;
    expire(&state.pool).await?;
    Ok(Json(view(&state.pool, &caller, id).await?))
}

pub async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(_input): Json<CancelReview>,
) -> Result<Json<ReviewView>, ApiError> {
    let caller = actor(&headers, &state)?;
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    let status: Option<String> = sqlx::query_scalar(
        "SELECT state FROM reviews WHERE id = $1 AND (requester_id = $2 OR $3) FOR UPDATE",
    )
    .bind(id)
    .bind(caller.id)
    .bind(caller.admin)
    .fetch_optional(&mut *tx)
    .await?;
    let status = status.ok_or_else(ApiError::missing)?;
    if !["awaiting_payment", "queued", "running", "cancelled"].contains(&status.as_str()) {
        return Err(ApiError::conflict("review_already_finished"));
    }
    sqlx::query("UPDATE reviews SET state = 'cancelled' WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sweep(&mut tx).await?;
    tx.commit().await?;
    Ok(Json(view(&state.pool, &caller, id).await?))
}

#[derive(FromRow)]
struct Worker {
    public_key: String,
    operator_id: Uuid,
    introduction: DbJson<DeviceIntroduction>,
    approval: String,
    private_work_approved: bool,
    website_reviews: bool,
    source_reviews: bool,
    live_tests: bool,
    live_tools: DbJson<Vec<patchriot_protocol::pentests::LiveToolProfile>>,
    paused: bool,
    last_seen_at: Option<DateTime<Utc>>,
    work_sequence: i64,
    work_reply: Option<DbJson<WorkReply>>,
}

async fn worker(tx: &mut Tx<'_>, id: Uuid, key: &str) -> Result<Worker, ApiError> {
    let worker = sqlx::query_as::<_, Worker>("SELECT public_key, operator_id, introduction, approval, private_work_approved, website_reviews, source_reviews, live_tests, live_tools, paused, last_seen_at, work_sequence, work_reply FROM devices WHERE id = $1 FOR UPDATE")
        .bind(id).fetch_optional(&mut **tx).await?.ok_or_else(ApiError::missing)?;
    if worker.public_key != key {
        return Err(ApiError::denied());
    }
    if worker.approval != "approved" {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "device_not_eligible"));
    }
    Ok(worker)
}

#[derive(FromRow)]
struct AssignmentRow {
    id: Uuid,
    review_id: Uuid,
    role: String,
    expires_at: DateTime<Utc>,
    mode: String,
    scenario: String,
    website_context: Option<DbJson<patchriot_protocol::website_reviews::WebsiteReviewContext>>,
    source_context: Option<DbJson<patchriot_protocol::sources::SourceReviewContext>>,
    pentest_context: Option<DbJson<patchriot_protocol::pentests::PentestContext>>,
}
impl AssignmentRow {
    fn assignment(self) -> Result<WorkAssignment, ApiError> {
        Ok(WorkAssignment {
            lease_id: self.id,
            review_id: self.review_id,
            role: role(&self.role)?,
            scenario: serde_json::from_value(serde_json::Value::String(self.scenario))?,
            expires_at: self.expires_at.timestamp(),
            mode: serde_json::from_value(serde_json::Value::String(self.mode))?,
            pentest: self.pentest_context.map(|context| {
                patchriot_protocol::pentests::PentestAssignment {
                    pentest_id: context.pentest_id,
                    scope_sha256: context.scope_sha256.clone(),
                }
            }),
            source: self.source_context.map(|context| {
                patchriot_protocol::sources::SourceAssignment {
                    source_id: context.source_id,
                    snapshot_sha256: context.snapshot_sha256.clone(),
                }
            }),
            website: self.website_context.map(|context| {
                patchriot_protocol::website_reviews::WebsiteAssignment {
                    site_check_id: context.site_check_id,
                    snapshot_sha256: context.snapshot_sha256.clone(),
                }
            }),
        })
    }
}

pub async fn poll(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<SignedRequest<WorkPoll>>,
) -> Result<Json<WorkReply>, ApiError> {
    verify(&request, &state, &format!("/v1/devices/{id}/work/poll"))?;
    let seq = request.payload.sequence;
    if seq == 0 || seq > i64::MAX as u64 {
        return Err(ApiError::bad("invalid_sequence"));
    }
    if request.payload.live_tools.len() > 3
        || request
            .payload
            .live_tools
            .iter()
            .enumerate()
            .any(|(i, t)| request.payload.live_tools[..i].contains(t))
        || (!request.payload.live_tests && !request.payload.live_tools.is_empty())
    {
        return Err(ApiError::bad("invalid_live_tools"));
    }
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    let device = worker(&mut tx, id, &request.public_key).await?;
    let mut modes = match device.introduction.runtime {
        RuntimeKind::OwnedFixture => vec!["owned_fixture"],
        RuntimeKind::Hermes if request.payload.live_tests => Vec::new(),
        RuntimeKind::Hermes => vec!["owned_agent"],
    };
    if (request.payload.website_reviews
        || request.payload.source_reviews
        || request.payload.live_tests)
        && device.introduction.runtime != RuntimeKind::Hermes
    {
        return Err(ApiError::bad("website_reviews_require_agent"));
    }
    if request.payload.live_tests
        && device.introduction.declared_model.as_deref() != Some("abliterated-model-large-v2")
    {
        return Err(ApiError::bad("live_model_not_supported"));
    }
    if device.private_work_approved {
        if request.payload.live_tests {
            modes.push("pentest_agent");
        }
        if request.payload.website_reviews {
            modes.push("website_agent");
        }
        if request.payload.source_reviews {
            modes.push("source_agent");
        }
    }
    if seq as i64 == device.work_sequence {
        if request.payload.website_reviews != device.website_reviews
            || request.payload.source_reviews != device.source_reviews
            || request.payload.live_tests != device.live_tests
            || request.payload.live_tools != device.live_tools.0
        {
            return Err(ApiError::conflict("conflicting_poll_replay"));
        }
        let reply = device
            .work_reply
            .ok_or_else(|| ApiError::conflict("invalid_poll_replay"))?
            .0;
        if reply
            .assignment
            .as_ref()
            .is_some_and(|a| !modes.contains(&a.mode.as_str()))
        {
            return Err(ApiError::new(StatusCode::FORBIDDEN, "device_not_eligible"));
        }
        tx.commit().await?;
        return Ok(Json(reply));
    }
    if (seq as i64) < device.work_sequence {
        return Err(ApiError::conflict("stale_work_poll"));
    }
    let mut assignment = None;
    if !device.paused
        && device
            .last_seen_at
            .is_some_and(|seen| now() - seen.timestamp() < 30)
    {
        let existing = sqlx::query_as::<_, AssignmentRow>("SELECT l.id, s.review_id, s.role, l.expires_at, r.mode, r.scenario, r.website_context, r.source_context, r.pentest_context FROM work_leases l JOIN review_steps s ON s.id = l.step_id JOIN reviews r ON r.id = s.review_id WHERE l.device_id = $1 AND l.state = 'active'")
            .bind(id).fetch_optional(&mut *tx).await?;
        if let Some(existing) = existing {
            if modes.contains(&existing.mode.as_str())
                && existing.pentest_context.as_ref().is_none_or(|c| {
                    c.scope
                        .tools
                        .iter()
                        .all(|t| request.payload.live_tools.contains(t))
                })
            {
                assignment = Some(existing.assignment()?);
            }
        } else {
            let busy: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM work_leases WHERE compute_group = $1 AND operator_id = $2 AND state = 'active')")
                .bind(&device.introduction.compute_group).bind(device.operator_id).fetch_one(&mut *tx).await?;
            if !busy {
                // Three distinct devices, sequential roles, and one shared-compute
                // slot. Actual operator independence is reported, never assumed.
                let step: Option<(Uuid, Uuid, String, i32)> = sqlx::query_as("SELECT s.id, s.review_id, r.mode, r.agent_attempt_seconds FROM review_steps s JOIN reviews r ON r.id = s.review_id WHERE s.state = 'queued' AND r.state IN ('queued','running') AND r.mode = ANY($2) AND (r.mode <> 'pentest_agent' OR $3::jsonb @> COALESCE(r.pentest_context->'scope'->'tools', '[]'::jsonb)) AND (s.assigned_device_id IS NULL OR s.assigned_device_id = $1) AND r.deadline_at > now() AND NOT EXISTS (SELECT 1 FROM review_steps previous WHERE previous.review_id = r.id AND previous.position < s.position AND previous.state <> 'completed') AND NOT EXISTS (SELECT 1 FROM review_steps used JOIN work_leases l ON l.id = used.current_lease_id WHERE used.review_id = r.id AND used.state = 'completed' AND l.device_id = $1) ORDER BY r.created_at, s.position LIMIT 1 FOR UPDATE OF s")
                    .bind(id).bind(&modes).bind(DbJson(&request.payload.live_tools)).fetch_optional(&mut *tx).await?;
                if let Some((step_id, review_id, mode, attempt_seconds)) = step {
                    let lease = Uuid::new_v4();
                    let seconds = if mode != "owned_fixture" {
                        attempt_seconds
                    } else {
                        60
                    };
                    sqlx::query("INSERT INTO work_leases (id, step_id, device_id, operator_id, compute_group, expires_at, deadline_at) SELECT $1,$2,$3,$4,$5,LEAST(now() + interval '60 seconds', deadline_at),LEAST(now() + make_interval(secs => $7), deadline_at) FROM reviews WHERE id = $6")
                        .bind(lease).bind(step_id).bind(id).bind(device.operator_id).bind(&device.introduction.compute_group).bind(review_id).bind(f64::from(seconds)).execute(&mut *tx).await?;
                    sqlx::query("UPDATE review_steps SET state = 'leased', attempts = attempts + 1, current_lease_id = $1 WHERE id = $2")
                        .bind(lease).bind(step_id).execute(&mut *tx).await?;
                    sqlx::query("UPDATE reviews SET state = 'running' WHERE id = $1")
                        .bind(review_id)
                        .execute(&mut *tx)
                        .await?;
                    assignment = Some(sqlx::query_as::<_, AssignmentRow>("SELECT l.id, s.review_id, s.role, l.expires_at, r.mode, r.scenario, r.website_context, r.source_context, r.pentest_context FROM work_leases l JOIN review_steps s ON s.id = l.step_id JOIN reviews r ON r.id = s.review_id WHERE l.id = $1")
                        .bind(lease).fetch_one(&mut *tx).await?.assignment()?);
                }
            }
        }
    }
    let reply = WorkReply { assignment };
    sqlx::query("UPDATE devices SET work_sequence = $1, work_reply = $2, website_reviews = $4, source_reviews = $5, live_tests = $6, live_tools = $7, work_polled_at = now() WHERE id = $3")
        .bind(seq as i64)
        .bind(DbJson(&reply))
        .bind(id)
        .bind(request.payload.website_reviews)
        .bind(request.payload.source_reviews)
        .bind(request.payload.live_tests)
        .bind(DbJson(&request.payload.live_tools))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(reply))
}

#[derive(FromRow)]
struct LeaseRow {
    step_id: Uuid,
    role: String,
    device_id: Uuid,
    review_id: Uuid,
    state: String,
    expires_at: DateTime<Utc>,
    deadline_at: DateTime<Utc>,
    renewal_sequence: i64,
    mode: String,
    result_hash: Option<String>,
    fixture_matches: Option<bool>,
    evidence_complete: Option<bool>,
    current_lease_id: Option<Uuid>,
}

async fn lease(tx: &mut Tx<'_>, id: Uuid) -> Result<LeaseRow, ApiError> {
    sqlx::query_as::<_, LeaseRow>("SELECT l.step_id, s.role, l.device_id, s.review_id, l.state, l.expires_at, LEAST(l.deadline_at, r.deadline_at) AS deadline_at, l.renewal_sequence, r.mode, l.result_hash, l.fixture_matches, l.evidence_complete, s.current_lease_id FROM work_leases l JOIN review_steps s ON s.id = l.step_id JOIN reviews r ON r.id = s.review_id WHERE l.id = $1 FOR UPDATE OF l, s")
        .bind(id).fetch_optional(&mut **tx).await?.ok_or_else(ApiError::missing)
}

fn active(lease: &LeaseRow, device_id: Uuid, lease_id: Uuid) -> Result<(), ApiError> {
    if lease.device_id != device_id {
        return Err(ApiError::denied());
    }
    if lease.state != "active"
        || lease.expires_at <= Utc::now()
        || lease.deadline_at <= Utc::now()
        || lease.current_lease_id != Some(lease_id)
    {
        return Err(ApiError::conflict("lease_no_longer_active"));
    }
    Ok(())
}

pub async fn renew(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<SignedRequest<RenewWork>>,
) -> Result<Json<WorkRenewed>, ApiError> {
    verify(&request, &state, &format!("/v1/devices/{id}/work/renew"))?;
    let input = request.payload;
    if input.sequence == 0 || input.sequence > i64::MAX as u64 {
        return Err(ApiError::bad("invalid_sequence"));
    }
    if input.progress.as_ref().is_some_and(|p| !p.valid()) {
        return Err(ApiError::bad("invalid_live_progress"));
    }
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    let device = worker(&mut tx, id, &request.public_key).await?;
    let current = lease(&mut tx, input.lease_id).await?;
    active(&current, id, input.lease_id)?;
    if input.progress.is_some() && current.mode != "pentest_agent" {
        return Err(ApiError::bad("live_progress_not_applicable"));
    }
    if current.mode == "pentest_agent" {
        let context = pentests::context(&mut tx, current.review_id).await?;
        if !context
            .scope
            .tools
            .iter()
            .all(|tool| device.live_tools.contains(tool))
        {
            return Err(ApiError::conflict("selected_tool_unavailable"));
        }
    }
    if (current.mode == "pentest_agent" && (!device.private_work_approved || !device.live_tests))
        || (current.mode == "website_agent"
            && (!device.private_work_approved || !device.website_reviews))
        || (current.mode == "source_agent"
            && (!device.private_work_approved || !device.source_reviews))
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "private_work_not_allowed",
        ));
    }
    if device.paused
        || device
            .last_seen_at
            .is_none_or(|seen| now() - seen.timestamp() >= 30)
    {
        return Err(ApiError::conflict("device_not_ready"));
    }
    if (input.sequence as i64) < current.renewal_sequence {
        return Err(ApiError::conflict("stale_renewal"));
    }
    let replayed = input.sequence as i64 == current.renewal_sequence;
    let expires = if replayed {
        current.expires_at
    } else {
        let progress = input.progress.map(|progress| {
            DbJson(patchriot_protocol::pentests::LiveProgressView {
                progress,
                received_at: now(),
            })
        });
        sqlx::query_scalar("UPDATE work_leases SET expires_at = LEAST(now() + interval '60 seconds', $1), renewal_sequence = $2, live_progress = COALESCE($4, live_progress) WHERE id = $3 RETURNING expires_at")
            .bind(current.deadline_at).bind(input.sequence as i64).bind(input.lease_id).bind(progress).fetch_one(&mut *tx).await?
    };
    tx.commit().await?;
    Ok(Json(WorkRenewed {
        lease_id: input.lease_id,
        sequence: input.sequence,
        expires_at: expires.timestamp(),
        deadline_at: current.deadline_at.timestamp(),
        valid_for_seconds: (expires - Utc::now()).num_seconds().max(0) as u64,
        replayed,
    }))
}

pub async fn complete(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<SignedRequest<CompleteWork>>,
) -> Result<Json<WorkAccepted>, ApiError> {
    verify(&request, &state, &format!("/v1/devices/{id}/work/complete"))?;
    let mut input = request.payload;
    if !matches!(input.result, WorkResult::Pentest(_))
        && serde_json::to_vec(&input)?.len() > 64 * 1024
    {
        return Err(ApiError::bad("result_too_large"));
    }
    let hash = payload_hash(&input)?;
    // Preserve the signed payload hash for replay checks. Binary response
    // excerpts cannot be stored as JSONB text; their source hashes remain intact.
    if let WorkResult::Pentest(result) = &mut input.result {
        result.omit_binary_excerpts();
    }
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    let device = worker(&mut tx, id, &request.public_key).await?;
    let lease = lease(&mut tx, input.lease_id).await?;
    if lease.device_id != id {
        return Err(ApiError::denied());
    }
    if lease.state == "completed" {
        if lease.result_hash.as_deref() != Some(&hash) {
            return Err(ApiError::conflict("conflicting_result"));
        }
        tx.commit().await?;
        return Ok(Json(WorkAccepted {
            accepted: true,
            replayed: true,
            fixture_matches: lease.fixture_matches.unwrap_or(false),
            evidence_complete: lease.evidence_complete,
        }));
    }
    active(&lease, id, input.lease_id)?;
    if input.result.mode().as_str() != lease.mode {
        return Err(ApiError::bad("wrong_result_kind"));
    }
    if let WorkResult::Agent(result) = &input.result
        && (!result.valid()
            || device.introduction.declared_model.as_deref() != Some(&result.declared_model))
    {
        return Err(ApiError::bad("invalid_agent_evidence"));
    }
    let (matches, evidence_complete) = if let WorkResult::Website(result) = &input.result {
        if !device.private_work_approved
            || !device.website_reviews
            || !result.valid()
            || device.introduction.declared_model.as_deref()
                != Some(&result.execution.declared_model)
        {
            return Err(ApiError::bad("invalid_website_evidence"));
        }
        let snapshot = websites::snapshot(&mut tx, lease.review_id).await?;
        if patchriot_protocol::website_reviews::snapshot_hash(&snapshot)? != result.snapshot_sha256
        {
            return Err(ApiError::bad("wrong_snapshot"));
        }
        (None, Some(result.evidence_complete(&snapshot)))
    } else if let WorkResult::Source(result) = &input.result {
        if !device.private_work_approved
            || !device.source_reviews
            || !result.valid()
            || device.introduction.declared_model.as_deref()
                != Some(&result.execution.declared_model)
        {
            return Err(ApiError::bad("invalid_source_evidence"));
        }
        let bundle = sources::bundle(&mut tx, lease.review_id).await?;
        if patchriot_protocol::sources::bundle_hash(&bundle)? != result.snapshot_sha256 {
            return Err(ApiError::bad("wrong_snapshot"));
        }
        (None, Some(result.evidence_complete(&bundle)))
    } else if let WorkResult::Pentest(result) = &mut input.result {
        let context = pentests::context(&mut tx, lease.review_id).await?;
        // Preserve raw model output, but accept an otherwise valid report with
        // ordinary introductory text. No missing fields or evidence are guessed.
        if result.assessment.is_none()
            && result.execution.state
                == patchriot_protocol::website_reviews::WebsiteRunState::Completed
        {
            result.assessment = patchriot_protocol::pentests::parse_assessment(&result.raw_summary);
            if !result.valid(&context.scope) {
                result.assessment = None;
            }
        }
        if !device.private_work_approved
            || !device.live_tests
            || !context
                .scope
                .tools
                .iter()
                .all(|tool| device.live_tools.contains(tool))
            || !result.valid(&context.scope)
            || device.introduction.declared_model.as_deref() != Some(&result.execution.model)
        {
            return Err(ApiError::bad("invalid_live_evidence"));
        }
        (
            None,
            Some(result.evidence_complete_for_role(&context.scope, role(&lease.role)?)),
        )
    } else {
        (Some(input.result.matches_fixture()), None)
    };
    sqlx::query("UPDATE work_leases SET state = 'completed', result_hash = $1, fixture_matches = $2, evidence_complete = $4 WHERE id = $3")
        .bind(hash).bind(matches).bind(input.lease_id).bind(evidence_complete).execute(&mut *tx).await?;
    sqlx::query("UPDATE review_steps SET state = 'completed', result = $1, fixture_matches = $2, evidence_complete = $4 WHERE id = $3")
        .bind(DbJson(input.result)).bind(matches).bind(lease.step_id).bind(evidence_complete).execute(&mut *tx).await?;
    sqlx::query("UPDATE reviews SET state = CASE WHEN (SELECT bool_and(CASE WHEN reviews.mode IN ('website_agent','source_agent','pentest_agent') THEN evidence_complete ELSE fixture_matches END) FROM review_steps WHERE review_id = $1) THEN 'completed' ELSE 'needs_review' END WHERE id = $1 AND NOT EXISTS (SELECT 1 FROM review_steps WHERE review_id = $1 AND state <> 'completed')")
        .bind(lease.review_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(WorkAccepted {
        accepted: true,
        replayed: false,
        fixture_matches: matches.unwrap_or(false),
        evidence_complete,
    }))
}
