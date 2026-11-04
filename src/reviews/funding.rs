//! Core admits the exact review before quoting and confirms a saved settlement
//! afterward. No HTTP call, quote creation, ledger mutation or payout runs here.

use super::*;
use patchriot_protocol::website_reviews::{AdmitWebsiteReview, FundReview};

pub(crate) async fn admit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(site_id): Path<Uuid>,
    Json(input): Json<AdmitWebsiteReview>,
) -> Result<Json<ReviewView>, ApiError> {
    let caller = actor(&headers, &state)?;
    Ok(Json(
        websites::create_review(
            &state,
            &caller,
            site_id,
            input.consent,
            Some((input.price, input.payment_expires_at)),
        )
        .await?,
    ))
}

/// An exact retry acknowledges the same activation, including after the review
/// finishes or is cancelled. It never revives work or extends its deadline.
pub(crate) async fn fund(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<FundReview>,
) -> Result<Json<ReviewView>, ApiError> {
    let caller = actor(&headers, &state)?;
    if !input.price.valid() || input.invoice_id.is_nil() {
        return Err(ApiError::bad("invalid_payment_terms"));
    }
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    // Even staff must act as the paying account. Payment never grants consent
    // on another requester's behalf.
    let current: ReviewRow = sqlx::query_as("SELECT id, request_id, state, mode, scenario, website_context, source_context, pentest_context, payment_terms, payment_expires_at, funded_invoice_id, funded_at, created_at, deadline_at, agent_attempt_seconds, per_role_timing, first_downloaded_at, report_expires_at FROM reviews WHERE id = $1 AND requester_id = $2 FOR UPDATE")
        .bind(id).bind(caller.id).fetch_optional(&mut *tx).await?.ok_or_else(ApiError::missing)?;
    if current.request_id != input.request_id
        || current.payment_terms.as_ref().map(|terms| &terms.0) != Some(&input.price)
    {
        return Err(ApiError::conflict("payment_does_not_match_review"));
    }
    if let Some(invoice) = current.funded_invoice_id {
        if invoice != input.invoice_id {
            return Err(ApiError::conflict("review_already_funded"));
        }
        tx.commit().await?;
        return Ok(Json(view(&state.pool, &caller, id).await?));
    }
    if current.state != "awaiting_payment"
        || current
            .payment_expires_at
            .is_none_or(|expires| expires <= Utc::now())
    {
        // Persist expiry/revocation cleanup even though the funding event is
        // rejected. Core must retain funds for its balance/refund policy.
        tx.commit().await?;
        return Err(ApiError::conflict("review_not_payable"));
    }
    let used: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM reviews WHERE funded_invoice_id = $1)")
            .bind(input.invoice_id)
            .fetch_one(&mut *tx)
            .await?;
    if used {
        return Err(ApiError::conflict("invoice_already_used"));
    }
    let review_seconds =
        patchriot_protocol::agent_review_seconds(current.agent_attempt_seconds as u64);
    let mut execution_deadline = Utc::now() + chrono::Duration::seconds(review_seconds as i64);
    if let Some(saved) = current.pentest_context {
        // Payment never extends domain permission or silently substitutes a
        // different operator. Re-check the scope when funds actually arrive.
        let context = pentests::context(&mut tx, id).await?;
        if context.scope_sha256 != saved.scope_sha256 || context.reviewers != saved.reviewers {
            return Err(ApiError::conflict("live_scope_not_ready"));
        }
        let ids: Vec<_> = context.reviewers.iter().map(|r| r.device_id).collect();
        let ready: Vec<_> = websites::eligible_with_tools(
            &mut tx,
            Some(&ids),
            ReviewMode::PentestAgent,
            &context.scope.tools,
        )
        .await?
        .into_iter()
        .map(websites::Candidate::disclosure)
        .collect();
        if ids.len() != 3
            || ready.len() != 3
            || context.reviewers.iter().any(|r| !ready.contains(r))
        {
            return Err(ApiError::conflict("selected_device_unavailable"));
        }
        let retained: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pentests WHERE id=$1 AND requester_id=$2 AND state='approved' AND (ownership_verified_at IS NOT NULL OR staff_authorized_at IS NOT NULL) AND expires_at > now() + make_interval(secs => $3))")
            .bind(context.pentest_id).bind(caller.id).bind(review_seconds as f64).fetch_one(&mut *tx).await?;
        if !retained {
            return Err(ApiError::conflict("live_scope_not_ready"));
        }
        if current.per_role_timing {
            execution_deadline = sqlx::query_scalar("SELECT LEAST(p.expires_at, now()+interval '24 hours', c.expires_at) FROM pentests p LEFT JOIN pentest_credentials c ON c.pentest_id=p.id WHERE p.id=$1")
                .bind(context.pentest_id).fetch_one(&mut *tx).await?;
            if execution_deadline < Utc::now() + chrono::Duration::seconds(review_seconds as i64) {
                return Err(ApiError::conflict("live_scope_not_ready"));
            }
        }
    } else if let Some(context) = current.source_context {
        let ids: Vec<_> = context.reviewers.iter().map(|r| r.device_id).collect();
        let ready = sources::candidates(&mut tx, Some(&ids)).await?;
        if ids.len() != 3
            || ready.len() != 3
            || context.reviewers.iter().any(|saved| !ready.contains(saved))
        {
            return Err(ApiError::conflict("selected_device_unavailable"));
        }
        let retained: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM source_uploads WHERE id = $1 AND state = 'approved' AND expires_at > now() + make_interval(secs => $2) AND bundle IS NOT NULL)")
            .bind(context.source_id).bind(review_seconds as f64).fetch_one(&mut *tx).await?;
        if !retained {
            return Err(ApiError::conflict("snapshot_retention_too_short"));
        }
        sources::bundle(&mut tx, id).await?;
    } else {
        let context = current
            .website_context
            .ok_or_else(|| ApiError::conflict("review_not_payable"))?;
        let ids: Vec<_> = context.reviewers.iter().map(|r| r.device_id).collect();
        let ready = websites::candidates(&mut tx, Some(&ids)).await?;
        if ids.len() != 3
            || ready.len() != 3
            || context.reviewers.iter().any(|saved| !ready.contains(saved))
        {
            return Err(ApiError::conflict("selected_device_unavailable"));
        }
        let retained: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM site_checks WHERE id = $1 AND evidence_expires_at > now() + make_interval(secs => $2) AND snapshot IS NOT NULL)")
            .bind(context.site_check_id).bind(review_seconds as f64).fetch_one(&mut *tx).await?;
        if !retained {
            return Err(ApiError::conflict("snapshot_retention_too_short"));
        }
        websites::snapshot(&mut tx, id).await?;
    }
    sqlx::query("UPDATE reviews SET state = 'queued', funded_invoice_id = $2, funded_at = now(), deadline_at = $3 WHERE id = $1")
        .bind(id).bind(input.invoice_id).bind(execution_deadline).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(Json(view(&state.pool, &caller, id).await?))
}
