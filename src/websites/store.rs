use super::normalize_scope;
use crate::{Actor, ApiError, AppState, actor};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, Utc};
use patchriot_protocol::websites::*;
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction, types::Json as DbJson};
use uuid::Uuid;

// Pilot limits are enforced under one short transaction lock, shared by admission
// and collection. No network operation or agent runs while holding that lock.
pub(super) async fn lock(tx: &mut Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(72638103)")
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub(super) async fn sweep(tx: &mut Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE site_checks SET state = 'failed', error = 'scope_expired', lease_id = NULL, lease_expires_at = NULL WHERE state IN ('pending_approval','queued','collecting') AND deadline_at <= now()")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE site_checks SET state = CASE WHEN attempts < 2 THEN 'queued' ELSE 'failed' END, error = CASE WHEN attempts < 2 THEN NULL ELSE 'collection_interrupted' END, lease_id = NULL, lease_expires_at = NULL WHERE state = 'collecting' AND lease_expires_at <= now()")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE site_checks SET snapshot = NULL WHERE snapshot IS NOT NULL AND evidence_expires_at <= now()")
        .execute(&mut **tx).await?;
    Ok(())
}

async fn expire(pool: &PgPool) -> Result<(), ApiError> {
    let mut tx = pool.begin().await?;
    lock(&mut tx).await?;
    sweep(&mut tx).await?;
    tx.commit().await?;
    Ok(())
}

#[derive(FromRow)]
struct SiteRow {
    id: Uuid,
    request_id: Uuid,
    requester_id: Uuid,
    scope: DbJson<WebsiteScope>,
    scope_sha256: String,
    authority_note: String,
    state: String,
    created_at: DateTime<Utc>,
    deadline_at: DateTime<Utc>,
    decided_by: Option<Uuid>,
    decision_note: Option<String>,
    attempts: i32,
    error: Option<String>,
    summary: Option<DbJson<WebsiteSummary>>,
    evidence_available: bool,
    evidence_expires_at: Option<DateTime<Utc>>,
}

async fn views(
    pool: &PgPool,
    caller: &Actor,
    id: Option<Uuid>,
) -> Result<Vec<SiteCheckView>, ApiError> {
    let rows = sqlx::query_as::<_, SiteRow>("SELECT id, request_id, requester_id, scope, scope_sha256, authority_note, state, created_at, deadline_at, decided_by, decision_note, attempts, error, summary, (snapshot IS NOT NULL AND evidence_expires_at > now()) AS evidence_available, evidence_expires_at FROM site_checks WHERE (requester_id = $1 OR $2) AND ($3::uuid IS NULL OR id = $3) ORDER BY created_at DESC LIMIT 20")
        .bind(caller.id).bind(caller.admin).bind(id).fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|r| SiteCheckView {
            id: r.id,
            request_id: r.request_id,
            requester_id: r.requester_id,
            scope: r.scope.0,
            scope_sha256: r.scope_sha256,
            authority_note: r.authority_note,
            state: r.state,
            created_at: r.created_at.timestamp(),
            deadline_at: r.deadline_at.timestamp(),
            decided_by: r.decided_by,
            decision_note: r.decision_note,
            attempts: r.attempts,
            error: r.error,
            summary: r.summary.map(|s| s.0),
            evidence_available: r.evidence_available,
            evidence_expires_at: r.evidence_expires_at.map(|d| d.timestamp()),
        })
        .collect())
}

async fn view(pool: &PgPool, caller: &Actor, id: Uuid) -> Result<SiteCheckView, ApiError> {
    views(pool, caller, Some(id))
        .await?
        .pop()
        .ok_or_else(ApiError::missing)
}

pub(crate) async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SiteCheckView>>, ApiError> {
    let caller = actor(&headers, &state)?;
    expire(&state.pool).await?;
    Ok(Json(views(&state.pool, &caller, None).await?))
}

pub(crate) async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<SiteCheckView>, ApiError> {
    let caller = actor(&headers, &state)?;
    expire(&state.pool).await?;
    Ok(Json(view(&state.pool, &caller, id).await?))
}

pub(crate) async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateSiteCheck>,
) -> Result<Json<SiteCheckView>, ApiError> {
    let caller = actor(&headers, &state)?;
    if !input.authorized {
        return Err(ApiError::bad("authority_required"));
    }
    let note = input.authority_note.trim();
    if !(12..=1200).contains(&note.len())
        || note
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return Err(ApiError::bad("invalid_authority_note"));
    }
    let scope = normalize_scope(&input.scope).map_err(ApiError::bad)?;
    let hash = format!("{:x}", Sha256::digest(serde_json::to_vec(&scope)?));
    let mut tx = state.pool.begin().await?;
    lock(&mut tx).await?;
    sweep(&mut tx).await?;
    let existing: Option<(Uuid, String, String)> = sqlx::query_as("SELECT id, scope_sha256, authority_note FROM site_checks WHERE requester_id = $1 AND request_id = $2")
        .bind(caller.id).bind(input.request_id).fetch_optional(&mut *tx).await?;
    if let Some((id, existing_hash, existing_note)) = existing {
        if hash != existing_hash || note != existing_note {
            return Err(ApiError::conflict("conflicting_site_request"));
        }
        tx.commit().await?;
        return Ok(Json(view(&state.pool, &caller, id).await?));
    }
    let (active, own, daily, own_daily): (i64,i64,i64,i64) = sqlx::query_as("SELECT count(*) FILTER (WHERE state IN ('pending_approval','queued','collecting')), count(*) FILTER (WHERE state IN ('pending_approval','queued','collecting') AND requester_id = $1), count(*) FILTER (WHERE created_at > now() - interval '24 hours'), count(*) FILTER (WHERE created_at > now() - interval '24 hours' AND requester_id = $1) FROM site_checks WHERE state IN ('pending_approval','queued','collecting') OR created_at > now() - interval '24 hours'")
        .bind(caller.id).fetch_one(&mut *tx).await?;
    if active >= 10 || own >= 2 || daily >= 10 || own_daily >= 3 {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "site_check_limit",
        ));
    }
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO site_checks (id,requester_id,request_id,scope,scope_sha256,authority_note) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(id).bind(caller.id).bind(input.request_id).bind(DbJson(scope)).bind(hash).bind(note).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(view(&state.pool, &caller, id).await?))
}

pub(crate) async fn decide(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<DecideSiteCheck>,
) -> Result<Json<SiteCheckView>, ApiError> {
    let caller = actor(&headers, &state)?;
    if !caller.admin {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "admin_required"));
    }
    let note = input.reason.trim();
    if !(12..=1200).contains(&note.len())
        || note
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t'))
    {
        return Err(ApiError::bad("invalid_decision_note"));
    }
    let action = match input.action {
        SiteDecision::Approve => "approve",
        SiteDecision::Reject => "reject",
    };
    let mut tx = state.pool.begin().await?;
    lock(&mut tx).await?;
    sweep(&mut tx).await?;
    let (status, hash, decision, reason): (String, String, Option<String>, Option<String>) = sqlx::query_as("SELECT state, scope_sha256, decision_action, decision_note FROM site_checks WHERE id = $1 FOR UPDATE")
        .bind(id).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::missing)?;
    if hash != input.scope_sha256 {
        return Err(ApiError::conflict("scope_changed"));
    }
    if decision.is_some() {
        if decision.as_deref() != Some(action) || reason.as_deref() != Some(note) {
            return Err(ApiError::conflict("decision_already_recorded"));
        }
    } else {
        if status != "pending_approval" {
            return Err(ApiError::conflict("site_check_not_pending"));
        }
        sqlx::query("UPDATE site_checks SET state = $2, decided_by = $3, decision_note = $4, decision_action = $5, decided_at = now(), deadline_at = CASE WHEN $5 = 'approve' THEN now() + interval '10 minutes' ELSE deadline_at END WHERE id = $1")
            .bind(id).bind(if input.action == SiteDecision::Approve { "queued" } else { "rejected" }).bind(caller.id).bind(note).bind(action).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(view(&state.pool, &caller, id).await?))
}

pub(crate) async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(_): Json<CancelSiteCheck>,
) -> Result<Json<SiteCheckView>, ApiError> {
    let caller = actor(&headers, &state)?;
    let mut tx = state.pool.begin().await?;
    lock(&mut tx).await?;
    sweep(&mut tx).await?;
    let status: String = sqlx::query_scalar(
        "SELECT state FROM site_checks WHERE id = $1 AND (requester_id = $2 OR $3) FOR UPDATE",
    )
    .bind(id)
    .bind(caller.id)
    .bind(caller.admin)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(ApiError::missing)?;
    if !["pending_approval", "queued", "collecting", "cancelled"].contains(&status.as_str()) {
        return Err(ApiError::conflict("site_check_finished"));
    }
    sqlx::query("UPDATE site_checks SET state = 'cancelled', lease_id = NULL, lease_expires_at = NULL WHERE id = $1")
        .bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(view(&state.pool, &caller, id).await?))
}

pub(crate) async fn artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<WebsiteSnapshot>, ApiError> {
    let caller = actor(&headers, &state)?;
    // Check ownership and retention in the same query. Never fetch a private blob
    // first and try to hide it later in the UI.
    let blob: DbJson<WebsiteSnapshot> = sqlx::query_scalar("SELECT snapshot FROM site_checks WHERE id = $1 AND (requester_id = $2 OR $3) AND state = 'collected' AND snapshot IS NOT NULL AND evidence_expires_at > now()")
        .bind(id).bind(caller.id).bind(caller.admin).fetch_optional(&state.pool).await?.ok_or_else(ApiError::missing)?;
    Ok(Json(blob.0))
}
