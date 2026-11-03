//! Export starts a fixed twelve-hour retention clock. Reads enforce it even if
//! cleanup is delayed. Payment facts and permission records are not findings.
use super::*;
use patchriot_protocol::reports::WorkReceipt;

pub(super) async fn purge(tx: &mut Tx<'_>) -> Result<(), ApiError> {
    sqlx::query("UPDATE review_steps s SET result=NULL FROM reviews r WHERE r.id=s.review_id AND r.report_expires_at<=now() AND r.report_purged_at IS NULL AND s.result IS NOT NULL")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE work_leases l SET live_progress=NULL FROM review_steps s,reviews r WHERE l.step_id=s.id AND s.review_id=r.id AND r.report_expires_at<=now() AND r.report_purged_at IS NULL AND l.live_progress IS NOT NULL")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE reviews SET report_purged_at=now() WHERE report_expires_at<=now() AND report_purged_at IS NULL")
        .execute(&mut **tx).await?;
    Ok(())
}

pub(crate) async fn download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(_input): Json<CancelReview>,
) -> Result<Json<ReviewView>, ApiError> {
    let caller = actor(&headers, &state)?;
    let mut tx = state.pool.begin().await?;
    scheduler(&mut tx).await?;
    sweep(&mut tx).await?;
    let saved: Option<(Uuid,String,Option<DateTime<Utc>>)> = sqlx::query_as("SELECT requester_id,state,report_expires_at FROM reviews WHERE id=$1 AND (requester_id=$2 OR $3) FOR UPDATE")
        .bind(id).bind(caller.id).bind(caller.admin).fetch_optional(&mut *tx).await?;
    let (requester, status, expires) = saved.ok_or_else(ApiError::missing)?;
    if expires.is_some_and(|expiry| expiry <= Utc::now()) {
        return Err(ApiError::new(StatusCode::GONE, "report_content_deleted"));
    }
    if matches!(status.as_str(), "awaiting_payment" | "queued" | "running") {
        return Err(ApiError::conflict("report_not_finished"));
    }
    if requester == caller.id && expires.is_none() {
        // Older reports predate work receipts. Save only accounting metadata
        // before their content can be removed, without inventing missing work.
        let rows: Vec<(Uuid,DbJson<WorkResult>)> = sqlx::query_as("SELECT id,result FROM review_steps WHERE review_id=$1 AND result IS NOT NULL AND work_receipt IS NULL")
            .bind(id).fetch_all(&mut *tx).await?;
        for (step, result) in rows {
            if let Some(receipt) = WorkReceipt::from_result(&result.0) {
                sqlx::query("UPDATE review_steps SET work_receipt=$2 WHERE id=$1")
                    .bind(step)
                    .bind(DbJson(receipt))
                    .execute(&mut *tx)
                    .await?;
            }
        }
        sqlx::query("UPDATE reviews SET first_downloaded_at=now(),report_expires_at=now()+interval '12 hours' WHERE id=$1 AND first_downloaded_at IS NULL")
            .bind(id).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    let result = view(&state.pool, &caller, id).await?;
    if result.retention.as_ref().is_some_and(|r| r.content_deleted) {
        return Err(ApiError::new(StatusCode::GONE, "report_content_deleted"));
    }
    Ok(Json(result))
}
