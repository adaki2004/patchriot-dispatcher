//! Consent binds one saved snapshot to three named devices. This module never
//! collects a URL or grants an agent network access.

use super::*;
use patchriot_protocol::{website_reviews::*, websites::WebsiteSnapshot};
use std::collections::HashSet;

#[derive(FromRow)]
struct Candidate {
    id: Uuid,
    operator_id: Uuid,
    operator_name: String,
    introduction: DbJson<DeviceIntroduction>,
}

impl Candidate {
    fn disclosure(self) -> WebsiteReviewer {
        WebsiteReviewer {
            device_id: self.id,
            operator_id: self.operator_id,
            operator_name: self.operator_name,
            device_name: self.introduction.label.clone(),
            declared_model: self.introduction.declared_model.clone().unwrap_or_default(),
            compute_group: self.introduction.compute_group.clone(),
        }
    }
}

async fn candidates(
    tx: &mut Tx<'_>,
    ids: Option<&[Uuid]>,
) -> Result<Vec<WebsiteReviewer>, ApiError> {
    // Introductions are immutable after pairing. A signed poll declares support
    // for this task, separately from staff approval and requester consent.
    let rows = sqlx::query_as::<_, Candidate>("SELECT d.id, d.operator_id, o.display_name AS operator_name, d.introduction FROM devices d JOIN operators o ON o.id = d.operator_id WHERE d.approval = 'approved' AND d.private_work_approved AND d.website_reviews AND NOT d.paused AND d.last_seen_at > now() - interval '30 seconds' AND d.introduction->>'runtime' = 'hermes' AND ($1::uuid[] IS NULL OR d.id = ANY($1)) ORDER BY d.created_at, d.id LIMIT 30 FOR UPDATE OF d")
        .bind(ids).fetch_all(&mut **tx).await?;
    Ok(rows.into_iter().map(Candidate::disclosure).collect())
}

async fn owned_snapshot(
    tx: &mut Tx<'_>,
    caller: &Actor,
    id: Uuid,
) -> Result<WebsiteSnapshot, ApiError> {
    let saved: DbJson<WebsiteSnapshot> = sqlx::query_scalar("SELECT snapshot FROM site_checks WHERE id = $1 AND (requester_id = $2 OR $3) AND state = 'collected' AND snapshot IS NOT NULL AND evidence_expires_at > now()")
        .bind(id).bind(caller.id).bind(caller.admin).fetch_optional(&mut **tx).await?.ok_or_else(ApiError::missing)?;
    Ok(saved.0)
}

pub(crate) async fn plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<WebsiteReviewPlan>, ApiError> {
    let caller = actor(&headers, &state)?;
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    let snapshot = owned_snapshot(&mut tx, &caller, id).await?;
    let candidates = candidates(&mut tx, None).await?;
    tx.commit().await?;
    Ok(Json(WebsiteReviewPlan {
        site_check_id: id,
        snapshot_sha256: snapshot_hash(&snapshot)?,
        candidates,
    }))
}

pub(crate) async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(site_id): Path<Uuid>,
    Json(input): Json<CreateWebsiteReview>,
) -> Result<Json<ReviewView>, ApiError> {
    let caller = actor(&headers, &state)?;
    if !input.accepts_operator_access
        || input.device_ids.len() != 3
        || input.device_ids.iter().collect::<HashSet<_>>().len() != 3
    {
        return Err(ApiError::bad("select_three_devices_and_consent"));
    }
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    let existing: Option<(Uuid, Option<DbJson<WebsiteReviewContext>>)> = sqlx::query_as(
        "SELECT id, website_context FROM reviews WHERE requester_id = $1 AND request_id = $2",
    )
    .bind(caller.id)
    .bind(input.request_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some((id, context)) = existing {
        let same = context.is_some_and(|context| {
            context.site_check_id == site_id
                && context.snapshot_sha256 == input.snapshot_sha256
                && context
                    .reviewers
                    .iter()
                    .map(|r| r.device_id)
                    .collect::<Vec<_>>()
                    == input.device_ids
        });
        if !same {
            return Err(ApiError::conflict("conflicting_review_request"));
        }
        tx.commit().await?;
        return Ok(Json(view(&state.pool, &caller, id).await?));
    }
    // Staff can inspect evidence but cannot consent to sharing on an owner's
    // behalf. Retention must cover the entire bounded review, including waiting.
    let owner: Option<Uuid> = sqlx::query_scalar("SELECT requester_id FROM site_checks WHERE id = $1 AND state = 'collected' AND snapshot IS NOT NULL AND evidence_expires_at > now() + interval '35 minutes'")
        .bind(site_id).fetch_optional(&mut *tx).await?;
    if owner != Some(caller.id) {
        return Err(ApiError::missing());
    }
    let snapshot = owned_snapshot(&mut tx, &caller, site_id).await?;
    if snapshot_hash(&snapshot)? != input.snapshot_sha256 {
        return Err(ApiError::conflict("snapshot_changed"));
    }
    let eligible = candidates(&mut tx, Some(&input.device_ids)).await?;
    let reviewers: Option<Vec<_>> = input
        .device_ids
        .iter()
        .map(|id| eligible.iter().find(|r| r.device_id == *id).cloned())
        .collect();
    let reviewers = reviewers.ok_or_else(|| ApiError::conflict("selected_device_unavailable"))?;
    let (total, own): (i64, i64) = sqlx::query_as("SELECT count(*), count(*) FILTER (WHERE requester_id = $1) FROM reviews WHERE state IN ('queued','running')")
        .bind(caller.id).fetch_one(&mut *tx).await?;
    if total >= 30 || own >= 3 {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "review_queue_full",
        ));
    }
    let id = Uuid::new_v4();
    let context = WebsiteReviewContext {
        site_check_id: site_id,
        snapshot_sha256: input.snapshot_sha256,
        reviewers,
    };
    sqlx::query("INSERT INTO reviews (id, requester_id, request_id, scenario, mode, deadline_at, site_check_id, website_context, consent_at) VALUES ($1,$2,$3,'website_snapshot_v1','website_agent',now() + interval '35 minutes',$4,$5,now())")
        .bind(id).bind(caller.id).bind(input.request_id).bind(site_id).bind(DbJson(&context)).execute(&mut *tx).await?;
    for (position, (role, device_id)) in [
        ReviewRole::Investigator,
        ReviewRole::Reproducer,
        ReviewRole::Challenger,
    ]
    .into_iter()
    .zip(input.device_ids)
    .enumerate()
    {
        sqlx::query("INSERT INTO review_steps (id, review_id, role, position, assigned_device_id) VALUES ($1,$2,$3,$4,$5)")
            .bind(Uuid::new_v4()).bind(id).bind(role.as_str()).bind(position as i16).bind(device_id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(Json(view(&state.pool, &caller, id).await?))
}

pub(super) async fn snapshot(tx: &mut Tx<'_>, review: Uuid) -> Result<WebsiteSnapshot, ApiError> {
    let (saved, context): (DbJson<WebsiteSnapshot>, DbJson<WebsiteReviewContext>) = sqlx::query_as("SELECT w.snapshot, r.website_context FROM reviews r JOIN site_checks w ON w.id = r.site_check_id WHERE r.id = $1 AND r.mode = 'website_agent' AND w.state = 'collected' AND w.snapshot IS NOT NULL AND w.evidence_expires_at > now()")
        .bind(review).fetch_optional(&mut **tx).await?.ok_or_else(ApiError::missing)?;
    if snapshot_hash(&saved.0)? != context.snapshot_sha256 {
        return Err(ApiError::conflict("snapshot_changed"));
    }
    Ok(saved.0)
}

pub(crate) async fn evidence(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<SignedRequest<ReadWorkEvidence>>,
) -> Result<Json<WebsiteWorkEvidence>, ApiError> {
    verify(&request, &state, &format!("/v1/devices/{id}/work/evidence"))?;
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    let device = worker(&mut tx, id, &request.public_key).await?;
    let current = lease(&mut tx, request.payload.lease_id).await?;
    active(&current, id, request.payload.lease_id)?;
    if current.mode != "website_agent" || !device.private_work_approved || !device.website_reviews {
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
    let snapshot = snapshot(&mut tx, current.review_id).await?;
    let previous: Vec<(String, bool, DbJson<WorkResult>)> = sqlx::query_as("SELECT role, evidence_complete, result FROM review_steps WHERE review_id = $1 AND state = 'completed' AND position < (SELECT position FROM review_steps WHERE id = $2) ORDER BY position")
        .bind(current.review_id).bind(current.step_id).fetch_all(&mut *tx).await?;
    let previous_reports = previous
        .into_iter()
        .map(|(name, evidence_complete, result)| {
            let WorkResult::Website(result) = result.0 else {
                return Err(ApiError::conflict("invalid_website_result"));
            };
            Ok(PriorWebsiteReport {
                role: role(&name)?,
                evidence_complete,
                assessment: result.assessment,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    tx.commit().await?;
    Ok(Json(WebsiteWorkEvidence {
        snapshot,
        previous_reports,
    }))
}
