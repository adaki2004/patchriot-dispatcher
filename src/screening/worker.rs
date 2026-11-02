use super::Jev;
use patchriot_protocol::websites::{RequestScreening, WebsiteScope};
use sqlx::{FromRow, PgPool, types::Json as DbJson};
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;

#[derive(FromRow)]
pub(super) struct Claim {
    pub id: Uuid,
    pub scope: DbJson<WebsiteScope>,
    pub authority_note: String,
    pub screening_claim: Uuid,
}

pub(super) async fn claim(pool: &PgPool) -> Result<Option<Claim>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    // One provider call across dispatcher instances. Never hold a transaction
    // while calling the provider. A restarted worker recovers the saved claim.
    sqlx::query("SELECT pg_advisory_xact_lock(72638110)")
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE site_checks SET screening_state = 'cancelled', screening_claim = NULL, screening_until = NULL WHERE screening_state IN ('queued','running') AND (state != 'pending_approval' OR deadline_at <= now())")
        .execute(&mut *tx).await?;
    sqlx::query("UPDATE site_checks SET screening_state = CASE WHEN screening_attempts < 2 THEN 'queued' ELSE 'unavailable' END, screening_claim = NULL, screening_until = NULL WHERE screening_state = 'running' AND screening_until <= now()")
        .execute(&mut *tx).await?;
    let result = sqlx::query_as::<_, Claim>("UPDATE site_checks SET screening_state = 'running', screening_claim = $1, screening_until = now() + interval '45 seconds', screening_attempts = screening_attempts + 1 WHERE id = (SELECT id FROM site_checks WHERE screening_state = 'queued' AND state = 'pending_approval' AND deadline_at > now() AND NOT EXISTS (SELECT 1 FROM site_checks WHERE screening_state = 'running') ORDER BY created_at LIMIT 1 FOR UPDATE) RETURNING id, scope, authority_note, screening_claim")
        .bind(Uuid::new_v4()).fetch_optional(&mut *tx).await?;
    tx.commit().await?;
    Ok(result)
}

pub(super) async fn finish(
    pool: &PgPool,
    claim: &Claim,
    result: Option<RequestScreening>,
) -> Result<bool, sqlx::Error> {
    let status = if result.is_some() {
        "complete"
    } else {
        "unavailable"
    };
    let rows = sqlx::query("UPDATE site_checks SET screening_state = $3, screening = $4, screening_claim = NULL, screening_until = NULL WHERE id = $1 AND screening_claim = $2 AND screening_state = 'running' AND screening_until > now() AND state = 'pending_approval' AND deadline_at > now()")
        .bind(claim.id).bind(claim.screening_claim).bind(status).bind(result.map(DbJson))
        .execute(pool).await?;
    Ok(rows.rows_affected() == 1)
}

async fn tick(pool: &PgPool, jev: Option<&Jev>) -> Result<(), sqlx::Error> {
    if let Some(claim) = claim(pool).await? {
        let result = match jev {
            Some(jev) => jev.assess(&claim.scope, &claim.authority_note).await,
            None => Err("screening_not_configured"),
        };
        if let Err(code) = &result {
            // Fixed error codes only: no provider body, account, URL or note.
            eprintln!("request screening failed: {code}");
        }
        finish(pool, &claim, result.ok()).await?;
    }
    Ok(())
}

/// Provider failure means manual review, never an automatic approval. Existing
/// quotas limit new requests to ten/day; each gets at most two attempts.
pub async fn run_worker(pool: PgPool, jev: Option<Jev>, mut stopped: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if *stopped.borrow() {
            break;
        }
        tokio::select! {
            _ = stopped.changed() => break,
            _ = interval.tick() => {
                tokio::select! {
                    _ = stopped.changed() => break,
                    result = tick(&pool, jev.as_ref()) => {
                        if result.is_err() { eprintln!("request screening database operation failed"); }
                    }
                }
            }
        }
    }
}
