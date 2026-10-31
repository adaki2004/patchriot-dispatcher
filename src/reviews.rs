//! A deliberately small queue for owned fixtures. No customer source, model calls
//! or payments enter this path. Leases bound retries and fence late results.

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

type Tx<'a> = Transaction<'a, Postgres>;

// A single short database lock keeps the prototype's queue/compute reservations
// consistent across HTTP requests. Never hold this lock across network or work.
async fn scheduler(tx: &mut Tx<'_>) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock(72638102)")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn sweep(tx: &mut Tx<'_>) -> Result<(), ApiError> {
    sqlx::query("UPDATE work_leases l SET state = 'expired' FROM review_steps s, reviews r, devices d WHERE l.state = 'active' AND s.id = l.step_id AND r.id = s.review_id AND d.id = l.device_id AND (l.expires_at <= now() OR r.deadline_at <= now() OR d.approval <> 'approved')")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE review_steps s SET state = CASE WHEN attempts < 3 THEN 'queued' ELSE 'failed' END FROM work_leases l WHERE s.current_lease_id = l.id AND s.state = 'leased' AND l.state = 'expired'")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE reviews r SET state = 'failed' WHERE r.state IN ('queued','running') AND (r.deadline_at <= now() OR EXISTS (SELECT 1 FROM review_steps s WHERE s.review_id = r.id AND s.state = 'failed'))")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE work_leases l SET state = 'cancelled' FROM review_steps s, reviews r WHERE s.id = l.step_id AND r.id = s.review_id AND r.state IN ('failed','cancelled') AND l.state = 'active'")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE review_steps s SET state = 'cancelled' FROM reviews r WHERE s.review_id = r.id AND r.state IN ('failed','cancelled') AND s.state IN ('queued','leased')")
        .execute(&mut **tx).await?;
    Ok(())
}

async fn expire(pool: &PgPool) -> Result<(), ApiError> {
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
    created_at: DateTime<Utc>,
    deadline_at: DateTime<Utc>,
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
    result: Option<DbJson<FixtureResult>>,
    fixture_matches: Option<bool>,
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
    let reviews = sqlx::query_as::<_, ReviewRow>("SELECT id, request_id, state, created_at, deadline_at FROM reviews WHERE (requester_id = $1 OR $2) AND ($3::uuid IS NULL OR id = $3) ORDER BY created_at DESC LIMIT 50")
        .bind(caller.id).bind(caller.admin).bind(id).fetch_all(pool).await?;
    let ids: Vec<_> = reviews.iter().map(|r| r.id).collect();
    let steps = sqlx::query_as::<_, StepRow>("SELECT s.review_id, s.role, s.state, s.attempts, l.device_id, l.operator_id, l.compute_group, CASE WHEN $2 THEN s.result ELSE NULL END AS result, s.fixture_matches FROM review_steps s LEFT JOIN work_leases l ON l.id = s.current_lease_id WHERE s.review_id = ANY($1) ORDER BY s.position")
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
            });
        }
        result.push(ReviewView {
            id: review.id,
            request_id: review.request_id,
            scenario: FixtureScenario::AccessControlV1,
            mode: "owned_fixture".into(),
            state: review.state,
            created_at: review.created_at.timestamp(),
            deadline_at: review.deadline_at.timestamp(),
            evidence_source: "device_reported_fixture_not_independently_verified".into(),
            steps: parts,
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
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    let existing: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM reviews WHERE requester_id = $1 AND request_id = $2")
            .bind(caller.id)
            .bind(input.request_id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some(id) = existing {
        tx.commit().await?;
        return Ok(Json(view(&state.pool, &caller, id).await?));
    }
    let (total, own): (i64, i64) = sqlx::query_as("SELECT count(*), count(*) FILTER (WHERE requester_id = $1) FROM reviews WHERE state IN ('queued','running')")
        .bind(caller.id).fetch_one(&mut *tx).await?;
    if total >= 30 || own >= 3 {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "fixture_queue_full",
        ));
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO reviews (id, requester_id, request_id, scenario) VALUES ($1,$2,$3,'access_control_v1')")
        .bind(id).bind(caller.id).bind(input.request_id).execute(&mut *tx).await?;
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
    if !["queued", "running", "cancelled"].contains(&status.as_str()) {
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
    paused: bool,
    last_seen_at: Option<DateTime<Utc>>,
    work_sequence: i64,
    work_reply: Option<DbJson<WorkReply>>,
}

async fn worker(tx: &mut Tx<'_>, id: Uuid, key: &str) -> Result<Worker, ApiError> {
    let worker = sqlx::query_as::<_, Worker>("SELECT public_key, operator_id, introduction, approval, paused, last_seen_at, work_sequence, work_reply FROM devices WHERE id = $1 FOR UPDATE")
        .bind(id).fetch_optional(&mut **tx).await?.ok_or_else(ApiError::missing)?;
    if worker.public_key != key {
        return Err(ApiError::denied());
    }
    if worker.approval != "approved" || worker.introduction.runtime != RuntimeKind::OwnedFixture {
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
}
impl AssignmentRow {
    fn assignment(self) -> Result<WorkAssignment, ApiError> {
        Ok(WorkAssignment {
            lease_id: self.id,
            review_id: self.review_id,
            role: role(&self.role)?,
            scenario: FixtureScenario::AccessControlV1,
            expires_at: self.expires_at.timestamp(),
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
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    let device = worker(&mut tx, id, &request.public_key).await?;
    if seq as i64 == device.work_sequence {
        let reply = device
            .work_reply
            .ok_or_else(|| ApiError::conflict("invalid_poll_replay"))?
            .0;
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
        let existing = sqlx::query_as::<_, AssignmentRow>("SELECT l.id, s.review_id, s.role, l.expires_at FROM work_leases l JOIN review_steps s ON s.id = l.step_id WHERE l.device_id = $1 AND l.state = 'active'")
            .bind(id).fetch_optional(&mut *tx).await?;
        if let Some(existing) = existing {
            assignment = Some(existing.assignment()?);
        } else {
            let busy: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM work_leases WHERE compute_group = $1 AND state = 'active')")
                .bind(&device.introduction.compute_group).fetch_one(&mut *tx).await?;
            if !busy {
                // Three distinct devices, sequential roles, and one shared-compute
                // slot. Actual operator independence is reported, never assumed.
                let step: Option<(Uuid, Uuid, String)> = sqlx::query_as("SELECT s.id, s.review_id, s.role FROM review_steps s JOIN reviews r ON r.id = s.review_id WHERE s.state = 'queued' AND r.state IN ('queued','running') AND r.deadline_at > now() AND NOT EXISTS (SELECT 1 FROM review_steps previous WHERE previous.review_id = r.id AND previous.position < s.position AND previous.state <> 'completed') AND NOT EXISTS (SELECT 1 FROM review_steps used JOIN work_leases l ON l.id = used.current_lease_id WHERE used.review_id = r.id AND used.state = 'completed' AND l.device_id = $1) ORDER BY r.created_at, s.position LIMIT 1 FOR UPDATE OF s")
                    .bind(id).fetch_optional(&mut *tx).await?;
                if let Some((step_id, review_id, step_role)) = step {
                    let lease = Uuid::new_v4();
                    let expires: DateTime<Utc> = sqlx::query_scalar("INSERT INTO work_leases (id, step_id, device_id, operator_id, compute_group, expires_at) VALUES ($1,$2,$3,$4,$5,LEAST(now() + interval '60 seconds', (SELECT deadline_at FROM reviews WHERE id = $6))) RETURNING expires_at")
                        .bind(lease).bind(step_id).bind(id).bind(device.operator_id).bind(&device.introduction.compute_group).bind(review_id).fetch_one(&mut *tx).await?;
                    sqlx::query("UPDATE review_steps SET state = 'leased', attempts = attempts + 1, current_lease_id = $1 WHERE id = $2")
                        .bind(lease).bind(step_id).execute(&mut *tx).await?;
                    sqlx::query("UPDATE reviews SET state = 'running' WHERE id = $1")
                        .bind(review_id)
                        .execute(&mut *tx)
                        .await?;
                    assignment = Some(WorkAssignment {
                        lease_id: lease,
                        review_id,
                        role: role(&step_role)?,
                        scenario: FixtureScenario::AccessControlV1,
                        expires_at: expires.timestamp(),
                    });
                }
            }
        }
    }
    let reply = WorkReply { assignment };
    sqlx::query("UPDATE devices SET work_sequence = $1, work_reply = $2 WHERE id = $3")
        .bind(seq as i64)
        .bind(DbJson(&reply))
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(reply))
}

#[derive(FromRow)]
struct LeaseRow {
    step_id: Uuid,
    device_id: Uuid,
    review_id: Uuid,
    state: String,
    expires_at: DateTime<Utc>,
    result_hash: Option<String>,
    fixture_matches: Option<bool>,
    current_lease_id: Option<Uuid>,
}

pub async fn complete(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<SignedRequest<CompleteWork>>,
) -> Result<Json<WorkAccepted>, ApiError> {
    verify(&request, &state, &format!("/v1/devices/{id}/work/complete"))?;
    let input = request.payload;
    let hash = payload_hash(&input)?;
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    worker(&mut tx, id, &request.public_key).await?;
    let lease = sqlx::query_as::<_, LeaseRow>("SELECT l.step_id, l.device_id, s.review_id, l.state, l.expires_at, l.result_hash, l.fixture_matches, s.current_lease_id FROM work_leases l JOIN review_steps s ON s.id = l.step_id WHERE l.id = $1 FOR UPDATE OF l, s")
        .bind(input.lease_id).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::missing)?;
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
        }));
    }
    if lease.state != "active"
        || lease.expires_at <= Utc::now()
        || lease.current_lease_id != Some(input.lease_id)
    {
        return Err(ApiError::conflict("lease_no_longer_active"));
    }
    let matches = input.result.matches_fixture();
    sqlx::query("UPDATE work_leases SET state = 'completed', result_hash = $1, fixture_matches = $2 WHERE id = $3")
        .bind(hash).bind(matches).bind(input.lease_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE review_steps SET state = 'completed', result = $1, fixture_matches = $2 WHERE id = $3")
        .bind(DbJson(input.result)).bind(matches).bind(lease.step_id).execute(&mut *tx).await?;
    sqlx::query("UPDATE reviews SET state = CASE WHEN (SELECT bool_and(fixture_matches) FROM review_steps WHERE review_id = $1) THEN 'completed' ELSE 'needs_review' END WHERE id = $1 AND NOT EXISTS (SELECT 1 FROM review_steps WHERE review_id = $1 AND state <> 'completed')")
        .bind(lease.review_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(WorkAccepted {
        accepted: true,
        replayed: false,
        fixture_matches: matches,
    }))
}
