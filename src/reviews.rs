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
pub(crate) mod retention;
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
    retention::purge(tx).await?;
    crate::sources::sweep(tx).await?;
    sqlx::query("UPDATE reviews r SET state='failed' WHERE r.mode='pentest_agent' AND r.state IN ('awaiting_payment','queued','running') AND r.pentest_context->'scope'->>'authentication' IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pentest_credentials c WHERE c.pentest_id=r.pentest_id AND c.expires_at>now())").execute(&mut **tx).await?;
    sqlx::query("UPDATE reviews r SET state = 'failed' WHERE r.mode = 'pentest_agent' AND r.state IN ('queued','running') AND (EXISTS (SELECT 1 FROM review_steps s JOIN devices d ON d.id = s.assigned_device_id WHERE s.review_id = r.id AND (d.approval <> 'approved' OR NOT d.private_work_approved)) OR NOT EXISTS (SELECT 1 FROM pentests p WHERE p.id = r.pentest_id AND p.state = 'approved' AND (p.ownership_verified_at IS NOT NULL OR p.staff_authorized_at IS NOT NULL) AND p.expires_at > now()))")
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
    per_role_timing: bool,
    first_downloaded_at: Option<DateTime<Utc>>,
    report_expires_at: Option<DateTime<Utc>>,
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
    work_receipt: Option<DbJson<patchriot_protocol::reports::WorkReceipt>>,
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
    let reviews = sqlx::query_as::<_, ReviewRow>("SELECT id, request_id, state, mode, scenario, website_context, source_context, pentest_context, payment_terms, payment_expires_at, funded_invoice_id, funded_at, created_at, deadline_at, agent_attempt_seconds, per_role_timing, first_downloaded_at, report_expires_at FROM reviews WHERE (requester_id = $1 OR $2) AND ($3::uuid IS NULL OR id = $3) ORDER BY created_at DESC LIMIT 50")
        .bind(caller.id).bind(caller.admin).bind(id).fetch_all(pool).await?;
    let ids: Vec<_> = reviews.iter().map(|r| r.id).collect();
    let steps = sqlx::query_as::<_, StepRow>("SELECT s.review_id, s.role, s.state, s.attempts, l.device_id, l.operator_id, l.compute_group, CASE WHEN $2 AND (r.report_expires_at IS NULL OR r.report_expires_at>now()) THEN s.result ELSE NULL END AS result, s.fixture_matches, s.evidence_complete, CASE WHEN r.report_expires_at IS NULL OR r.report_expires_at>now() THEN l.live_progress ELSE NULL END AS live_progress, CASE WHEN $2 THEN s.work_receipt ELSE NULL END AS work_receipt FROM review_steps s JOIN reviews r ON r.id=s.review_id LEFT JOIN work_leases l ON l.id = s.current_lease_id WHERE s.review_id = ANY($1) ORDER BY s.position")
        .bind(&ids).bind(id.is_some()).fetch_all(pool).await?;
    let mut result = Vec::new();
    for review in reviews {
        let timing = if review.per_role_timing && id.is_some() {
            let (started, active): (Option<DateTime<Utc>>, Option<DateTime<Utc>>) = sqlx::query_as("SELECT min(l.created_at), max(l.deadline_at) FILTER (WHERE l.state='active') FROM work_leases l JOIN review_steps s ON s.id=l.step_id WHERE s.review_id=$1")
                .bind(review.id).fetch_one(pool).await?;
            let ahead: i64 = if matches!(review.state.as_str(), "queued" | "running") {
                sqlx::query_scalar("SELECT count(*) FROM reviews earlier WHERE earlier.mode='pentest_agent' AND earlier.state IN ('queued','running') AND (COALESCE(earlier.funded_at,earlier.created_at),earlier.id)<($2,$1) AND EXISTS(SELECT 1 FROM review_steps mine JOIN devices md ON md.id=mine.assigned_device_id JOIN review_steps other ON other.review_id=earlier.id JOIN devices od ON od.id=other.assigned_device_id WHERE mine.review_id=$1 AND mine.state IN ('queued','leased') AND other.state IN ('queued','leased') AND md.operator_id=od.operator_id AND md.introduction->>'compute_group'=od.introduction->>'compute_group')")
                    .bind(review.id).bind(review.funded_at.unwrap_or(review.created_at)).fetch_one(pool).await?
            } else {
                0
            };
            Some(ReviewTiming {
                role_limit_seconds: review.agent_attempt_seconds as u64,
                started_at: started.map(|t| t.timestamp()),
                active_role_deadline_at: active.map(|t| t.timestamp()),
                requests_ahead: ahead as u32,
            })
        } else {
            None
        };
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
                receipt: step.work_receipt.as_ref().map(|r| r.0.clone()),
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
            timing,
            retention: review
                .first_downloaded_at
                .zip(review.report_expires_at)
                .map(
                    |(first, expires)| patchriot_protocol::reports::ReportRetention {
                        first_downloaded_at: first.timestamp(),
                        expires_at: expires.timestamp(),
                        content_deleted: expires <= Utc::now(),
                    },
                ),
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

/// Read-only counts across the full history, independent of the 50-row lists.
pub async fn stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ReviewStats>, ApiError> {
    let caller = actor(&headers, &state)?;
    if !caller.admin {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "admin_required"));
    }
    #[derive(FromRow)]
    struct Counts {
        requested: i64,
        live_requested: i64,
        awaiting_verification: i64,
        review_runs: i64,
        awaiting_payment: i64,
        queued: i64,
        running: i64,
        completed: i64,
        needs_review: i64,
        failed: i64,
        cancelled: i64,
        as_of: i64,
    }
    let c:Counts=sqlx::query_as("SELECT (SELECT count(*) FROM pentests)+(SELECT count(*) FROM site_checks)+(SELECT count(*) FROM source_uploads) AS requested,(SELECT count(*) FROM pentests) AS live_requested,(SELECT count(*) FROM pentests WHERE state='pending_approval' AND ownership_verified_at IS NULL AND staff_authorized_at IS NULL AND expires_at>now()) AS awaiting_verification,count(*) AS review_runs,count(*) FILTER(WHERE state='awaiting_payment') AS awaiting_payment,count(*) FILTER(WHERE state='queued') AS queued,count(*) FILTER(WHERE state='running') AS running,count(*) FILTER(WHERE state='completed') AS completed,count(*) FILTER(WHERE state='needs_review') AS needs_review,count(*) FILTER(WHERE state='failed') AS failed,count(*) FILTER(WHERE state='cancelled') AS cancelled,extract(epoch FROM now())::bigint AS as_of FROM reviews").fetch_one(&state.pool).await?;
    Ok(Json(ReviewStats {
        requested: c.requested,
        live_requested: c.live_requested,
        awaiting_verification: c.awaiting_verification,
        review_runs: c.review_runs,
        awaiting_payment: c.awaiting_payment,
        queued: c.queued,
        running: c.running,
        completed: c.completed,
        needs_review: c.needs_review,
        failed: c.failed,
        cancelled: c.cancelled,
        as_of: c.as_of,
    }))
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

/// Choose across the shared machine, not just the device that polled first.
/// An unavailable pinned worker does not stall unrelated ready work. This
/// chooses no substitute operator and the existing compute lease stays the
/// final guard against running two tasks on the same declared machine.
async fn next_live_step(
    tx: &mut Tx<'_>,
    id: Uuid,
    device: &Worker,
    tools: &[patchriot_protocol::pentests::LiveToolProfile],
) -> Result<Option<Uuid>, ApiError> {
    let next: Option<(Uuid, Uuid)> = sqlx::query_as(r#"
        SELECT s.id, d.id FROM review_steps s
        JOIN reviews r ON r.id=s.review_id
        JOIN devices d ON d.id=s.assigned_device_id
        WHERE r.mode='pentest_agent' AND r.state IN ('queued','running')
          AND s.state='queued' AND r.deadline_at>now()
          AND d.operator_id=$2 AND d.introduction->>'compute_group'=$3
          AND d.approval='approved' AND d.private_work_approved AND NOT d.paused
          AND d.last_seen_at>now()-interval '30 seconds'
          AND d.introduction->>'runtime'='hermes'
          AND d.introduction->>'declared_model'=ANY($5)
          AND (d.id=$1 OR (d.live_tests AND d.work_polled_at>now()-interval '30 seconds'))
          AND NOT EXISTS(SELECT 1 FROM work_leases busy WHERE busy.device_id=d.id AND busy.state='active')
          AND (CASE WHEN d.id=$1 THEN $4::jsonb ELSE d.live_tools END)
              @> COALESCE(r.pentest_context->'scope'->'tools','[]'::jsonb)
          AND NOT EXISTS(SELECT 1 FROM review_steps previous
              WHERE previous.review_id=r.id AND previous.position<s.position AND previous.state<>'completed')
          AND NOT EXISTS(SELECT 1 FROM review_steps used JOIN work_leases l ON l.id=used.current_lease_id
              WHERE used.review_id=r.id AND used.state='completed' AND l.device_id=d.id)
        ORDER BY COALESCE(r.funded_at,r.created_at), r.id, s.position
        LIMIT 1 FOR UPDATE OF s
    "#).bind(id).bind(device.operator_id).bind(&device.introduction.compute_group)
        .bind(DbJson(tools)).bind(&patchriot_protocol::pentests::LiveProvider::MODELS[..]).fetch_optional(&mut **tx).await?;
    Ok(next
        .filter(|(_, assigned)| *assigned == id)
        .map(|(step, _)| step))
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
    if request.payload.live_tools.len() > 9
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
        && device
            .introduction
            .declared_model
            .as_deref()
            .and_then(patchriot_protocol::pentests::LiveProvider::from_model)
            .is_none()
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
            // The scheduler transaction lock makes counting and assignment
            // atomic across gateways. Lowering the limit lets existing work
            // finish before another role can take a slot.
            let active: i64 = sqlx::query_scalar("SELECT count(*) FROM work_leases WHERE compute_group = $1 AND operator_id = $2 AND state = 'active'")
                .bind(&device.introduction.compute_group).bind(device.operator_id).fetch_one(&mut *tx).await?;
            if active < i64::from(state.compute_group_concurrency) {
                let next_live = if modes.contains(&"pentest_agent") {
                    next_live_step(&mut tx, id, &device, &request.payload.live_tools).await?
                } else {
                    None
                };
                // Roles within a review stay sequential and use distinct devices.
                // Spare host slots can serve other reviews without changing identity.
                let step: Option<(Uuid, Uuid, String, i32)> = sqlx::query_as("SELECT s.id, s.review_id, r.mode, r.agent_attempt_seconds FROM review_steps s JOIN reviews r ON r.id = s.review_id WHERE s.state = 'queued' AND r.state IN ('queued','running') AND r.mode = ANY($2) AND (r.mode <> 'pentest_agent' OR s.id=$4) AND (r.mode <> 'pentest_agent' OR $3::jsonb @> COALESCE(r.pentest_context->'scope'->'tools', '[]'::jsonb)) AND (s.assigned_device_id IS NULL OR s.assigned_device_id = $1) AND r.deadline_at > now() AND NOT EXISTS (SELECT 1 FROM review_steps previous WHERE previous.review_id = r.id AND previous.position < s.position AND previous.state <> 'completed') AND NOT EXISTS (SELECT 1 FROM review_steps used JOIN work_leases l ON l.id = used.current_lease_id WHERE used.review_id = r.id AND used.state = 'completed' AND l.device_id = $1) ORDER BY r.created_at, s.position LIMIT 1 FOR UPDATE OF s")
                    .bind(id).bind(&modes).bind(DbJson(&request.payload.live_tools)).bind(next_live).fetch_optional(&mut *tx).await?;
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
    // A signed renewal proves presence for this still-active lease. The shorter
    // heartbeat freshness rule governs new assignments, and must not cancel an
    // existing 60-second lease after a delayed heartbeat. active() above still
    // enforces expiry, replacement and the fixed review/attempt deadline.
    if device.paused {
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
            || !context.permits_fallback(&result.execution)
            || device.introduction.declared_model.as_deref() != Some(&result.execution.model)
        {
            return Err(ApiError::bad("invalid_live_evidence"));
        }
        if let Some(workflow) = &result.workflow {
            let previous: Vec<(String, DbJson<WorkResult>)> = sqlx::query_as("SELECT role,result FROM review_steps WHERE review_id=$1 AND state='completed' AND position<(SELECT position FROM review_steps WHERE id=$2) ORDER BY position")
                .bind(lease.review_id).bind(lease.step_id).fetch_all(&mut *tx).await?;
            let previous = previous
                .into_iter()
                .filter_map(|(name, saved)| {
                    let WorkResult::Pentest(saved) = saved.0 else {
                        return None;
                    };
                    Some(Ok(patchriot_protocol::pentests::PriorPentestReport {
                        role: match role(&name) {
                            Ok(role) => role,
                            Err(error) => return Some(Err(error)),
                        },
                        assessment: saved.assessment,
                        evidence: saved.evidence,
                        tool_runs: saved.tool_runs,
                    }))
                })
                .collect::<Result<Vec<_>, ApiError>>()?;
            if !workflow.valid_reuse(&context.scope, role(&lease.role)?, &previous) {
                return Err(ApiError::bad("invalid_live_workflow_reuse"));
            }
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
    let receipt = patchriot_protocol::reports::WorkReceipt::from_result(&input.result).map(DbJson);
    sqlx::query("UPDATE review_steps SET state = 'completed', result = $1, fixture_matches = $2, evidence_complete = $4, work_receipt=$5 WHERE id = $3")
        .bind(DbJson(input.result)).bind(matches).bind(lease.step_id).bind(evidence_complete).bind(receipt).execute(&mut *tx).await?;
    if lease.mode == "pentest_agent" {
        pentests::advance(&mut tx, lease.review_id).await?;
    }
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
