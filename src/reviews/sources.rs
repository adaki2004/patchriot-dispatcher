//! Reviews of immutable, approved source uploads. No path is opened or executed.
use super::*;
use patchriot_protocol::{
    sources::*,
    website_reviews::{ReadWorkEvidence, ReviewPrice, WebsiteReviewer},
};
use std::collections::HashSet;

pub(super) async fn candidates(
    tx: &mut Tx<'_>,
    ids: Option<&[Uuid]>,
) -> Result<Vec<WebsiteReviewer>, ApiError> {
    Ok(websites::eligible(tx, ids, ReviewMode::SourceAgent)
        .await?
        .into_iter()
        .map(websites::Candidate::disclosure)
        .collect())
}
async fn owned_bundle(tx: &mut Tx<'_>, caller: &Actor, id: Uuid) -> Result<SourceBundle, ApiError> {
    let saved: DbJson<SourceBundle> = sqlx::query_scalar("SELECT bundle FROM source_uploads WHERE id = $1 AND (requester_id = $2 OR $3) AND state = 'approved' AND bundle IS NOT NULL AND expires_at > now()")
        .bind(id).bind(caller.id).bind(caller.admin).fetch_optional(&mut **tx).await?.ok_or_else(ApiError::missing)?;
    Ok(saved.0)
}
pub(crate) async fn plan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<SourceReviewPlan>, ApiError> {
    let caller = actor(&headers, &state)?;
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    let bundle = owned_bundle(&mut tx, &caller, id).await?;
    let candidates = websites::eligible(&mut tx, None, ReviewMode::SourceAgent).await?;
    let recommended_device_ids = websites::recommend(&candidates, id);
    tx.commit().await?;
    Ok(Json(SourceReviewPlan {
        review_timeout_seconds: state.agent_review_seconds(),
        source_id: id,
        snapshot_sha256: bundle_hash(&bundle)?,
        candidates: candidates
            .into_iter()
            .map(websites::Candidate::disclosure)
            .collect(),
        recommended_device_ids,
    }))
}
pub(crate) async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<CreateSourceReview>,
) -> Result<Json<ReviewView>, ApiError> {
    let caller = actor(&headers, &state)?;
    Ok(Json(create_review(&state, &caller, id, input, None).await?))
}
pub(crate) async fn admit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<AdmitSourceReview>,
) -> Result<Json<ReviewView>, ApiError> {
    let caller = actor(&headers, &state)?;
    Ok(Json(
        create_review(
            &state,
            &caller,
            id,
            input.consent,
            Some((input.price, input.payment_expires_at)),
        )
        .await?,
    ))
}

pub(super) async fn create_review(
    state: &AppState,
    caller: &Actor,
    source_id: Uuid,
    input: CreateSourceReview,
    payment: Option<(ReviewPrice, i64)>,
) -> Result<ReviewView, ApiError> {
    if !input.accepts_operator_access
        || input.device_ids.len() != 3
        || input.device_ids.iter().collect::<HashSet<_>>().len() != 3
    {
        return Err(ApiError::bad("select_three_devices_and_consent"));
    }
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    let existing: Option<ReviewRow> = sqlx::query_as(
        "SELECT id, request_id, state, mode, scenario, website_context, source_context, pentest_context, payment_terms, payment_expires_at, funded_invoice_id, funded_at, created_at, deadline_at, agent_attempt_seconds FROM reviews WHERE requester_id = $1 AND request_id = $2",
    )
    .bind(caller.id)
    .bind(input.request_id)
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(existing) = existing {
        let same = existing.source_context.is_some_and(|context| {
            context.source_id == source_id
                && context.snapshot_sha256 == input.snapshot_sha256
                && context
                    .reviewers
                    .iter()
                    .map(|r| r.device_id)
                    .collect::<Vec<_>>()
                    == input.device_ids
        });
        let same_payment = existing.payment_terms.map(|terms| terms.0)
            == payment.as_ref().map(|(price, _)| price.clone())
            && existing.payment_expires_at.map(|time| time.timestamp())
                == payment.as_ref().map(|(_, expires)| *expires);
        if !same || !same_payment {
            return Err(ApiError::conflict("conflicting_review_request"));
        }
        tx.commit().await?;
        return view(&state.pool, caller, existing.id).await;
    }
    let payment_deadline = match &payment {
        Some((price, expires)) if price.valid() && *expires > now() && *expires <= now() + 3600 => {
            Some(
                DateTime::from_timestamp(*expires, 0)
                    .ok_or_else(|| ApiError::bad("invalid_payment_terms"))?,
            )
        }
        Some(_) => return Err(ApiError::bad("invalid_payment_terms")),
        None => None,
    };
    let review_seconds = state.agent_review_seconds();
    let retained_until = payment_deadline.unwrap_or_else(Utc::now)
        + chrono::Duration::seconds(review_seconds as i64);
    // Staff can inspect evidence but cannot consent to sharing on an owner's
    // behalf. Retention must cover the entire bounded review, including waiting.
    let owner: Option<Uuid> = sqlx::query_scalar("SELECT requester_id FROM source_uploads WHERE id = $1 AND state = 'approved' AND bundle IS NOT NULL AND expires_at > $2")
        .bind(source_id).bind(retained_until).fetch_optional(&mut *tx).await?;
    if owner != Some(caller.id) {
        return Err(ApiError::missing());
    }
    let snapshot = owned_bundle(&mut tx, caller, source_id).await?;
    if bundle_hash(&snapshot)? != input.snapshot_sha256 {
        return Err(ApiError::conflict("snapshot_changed"));
    }
    let eligible = candidates(&mut tx, Some(&input.device_ids)).await?;
    let reviewers: Option<Vec<_>> = input
        .device_ids
        .iter()
        .map(|id| eligible.iter().find(|r| r.device_id == *id).cloned())
        .collect();
    let reviewers = reviewers.ok_or_else(|| ApiError::conflict("selected_device_unavailable"))?;
    let (total, own): (i64, i64) = sqlx::query_as("SELECT count(*), count(*) FILTER (WHERE requester_id = $1) FROM reviews WHERE state IN ('awaiting_payment','queued','running')")
        .bind(caller.id).fetch_one(&mut *tx).await?;
    if total >= 30 || own >= 3 {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "review_queue_full",
        ));
    }
    let id = Uuid::new_v4();
    let context = SourceReviewContext {
        source_id,
        snapshot_sha256: input.snapshot_sha256,
        reviewers,
    };
    sqlx::query("INSERT INTO reviews (id, requester_id, request_id, scenario, mode, deadline_at, source_id, source_context, consent_at, state, payment_terms, payment_expires_at, agent_attempt_seconds) VALUES ($1,$2,$3,'source_bundle_v1','source_agent',COALESCE($6::timestamptz,now() + make_interval(secs => $10)),$4,$5,now(),$7,$8,$9,$11)")
        .bind(id).bind(caller.id).bind(input.request_id).bind(source_id).bind(DbJson(&context))
        .bind(payment_deadline)
        .bind(if payment.is_some() { "awaiting_payment" } else { "queued" })
        .bind(payment.as_ref().map(|(price, _)| DbJson(price)))
        .bind(payment_deadline).bind(review_seconds as f64).bind(state.agent_attempt_seconds as i32).execute(&mut *tx).await?;
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
    view(&state.pool, caller, id).await
}

pub(super) async fn bundle(tx: &mut Tx<'_>, review: Uuid) -> Result<SourceBundle, ApiError> {
    let (saved, context): (DbJson<SourceBundle>, DbJson<SourceReviewContext>) = sqlx::query_as("SELECT u.bundle, r.source_context FROM reviews r JOIN source_uploads u ON u.id = r.source_id WHERE r.id = $1 AND r.mode = 'source_agent' AND u.state = 'approved' AND u.bundle IS NOT NULL AND u.expires_at > now()")
        .bind(review).fetch_optional(&mut **tx).await?.ok_or_else(ApiError::missing)?;
    if !saved.valid() || bundle_hash(&saved.0)? != context.snapshot_sha256 {
        return Err(ApiError::conflict("source_changed"));
    }
    Ok(saved.0)
}
pub(crate) async fn evidence(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<SignedRequest<ReadWorkEvidence>>,
) -> Result<Json<SourceWorkEvidence>, ApiError> {
    verify(
        &request,
        &state,
        &format!("/v1/devices/{id}/work/source-evidence"),
    )?;
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    let device = worker(&mut tx, id, &request.public_key).await?;
    let current = lease(&mut tx, request.payload.lease_id).await?;
    active(&current, id, request.payload.lease_id)?;
    if current.mode != "source_agent" || !device.private_work_approved || !device.source_reviews {
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
    let bundle = bundle(&mut tx, current.review_id).await?;
    let previous: Vec<(String,bool,DbJson<WorkResult>)> = sqlx::query_as("SELECT role,evidence_complete,result FROM review_steps WHERE review_id = $1 AND state = 'completed' AND position < (SELECT position FROM review_steps WHERE id = $2) ORDER BY position")
        .bind(current.review_id).bind(current.step_id).fetch_all(&mut *tx).await?;
    let previous_reports = previous
        .into_iter()
        .map(|(name, evidence_complete, result)| {
            let WorkResult::Source(result) = result.0 else {
                return Err(ApiError::conflict("invalid_source_result"));
            };
            Ok(PriorSourceReport {
                role: role(&name)?,
                evidence_complete,
                assessment: result.assessment,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    tx.commit().await?;
    Ok(Json(SourceWorkEvidence {
        bundle,
        previous_reports,
    }))
}
