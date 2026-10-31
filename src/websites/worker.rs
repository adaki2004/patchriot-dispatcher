use super::{CollectionError, collect, store};
use patchriot_protocol::websites::{
    ResourceKind, ScriptStatus, WebsiteScope, WebsiteSnapshot, WebsiteSummary,
};
use sqlx::{FromRow, PgPool, types::Json as DbJson};
use std::time::Duration;
use tokio::sync::watch;
use uuid::Uuid;

#[derive(FromRow)]
pub(super) struct CollectionLease {
    pub id: Uuid,
    pub lease_id: Uuid,
    pub scope: DbJson<WebsiteScope>,
}

pub(super) async fn claim(pool: &PgPool) -> Result<Option<CollectionLease>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    store::lock(&mut tx).await?;
    store::sweep(&mut tx).await?;
    let busy: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM site_checks WHERE state = 'collecting')")
            .fetch_one(&mut *tx)
            .await?;
    if busy {
        tx.commit().await?;
        return Ok(None);
    }
    let id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM site_checks WHERE state = 'queued' ORDER BY created_at, id LIMIT 1 FOR UPDATE")
        .fetch_optional(&mut *tx).await?;
    let lease = if let Some(id) = id {
        sqlx::query_as("UPDATE site_checks SET state = 'collecting', attempts = attempts + 1, lease_id = $2, lease_expires_at = LEAST(deadline_at, now() + interval '45 seconds') WHERE id = $1 RETURNING id, lease_id, scope")
            .bind(id).bind(Uuid::new_v4()).fetch_optional(&mut *tx).await?
    } else {
        None
    };
    tx.commit().await?;
    Ok(lease)
}

pub(super) async fn current(pool: &PgPool, lease: &CollectionLease) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM site_checks WHERE id = $1 AND lease_id = $2 AND state = 'collecting' AND lease_expires_at > now() AND deadline_at > now())")
        .bind(lease.id).bind(lease.lease_id).fetch_one(pool).await
}

pub(super) async fn finish(
    pool: &PgPool,
    lease: &CollectionLease,
    result: Result<WebsiteSnapshot, CollectionError>,
) -> Result<bool, sqlx::Error> {
    let result = result.and_then(|snapshot| {
        if snapshot.scope != lease.scope.0 {
            return Err(CollectionError("snapshot_scope_mismatch"));
        }
        // Leave room for JSONB's whitespace below the database's 5 MiB limit.
        if serde_json::to_vec(&snapshot).map_or(true, |bytes| bytes.len() > 4 * 1024 * 1024) {
            return Err(CollectionError("snapshot_too_large"));
        }
        Ok(snapshot)
    });
    let (state, error, summary, snapshot) = match result {
        Ok(snapshot) => {
            let summary = WebsiteSummary {
                homepage_sha256: snapshot.homepage.sha256.clone(),
                external_scripts: snapshot
                    .resources
                    .iter()
                    .filter(|r| r.kind == ResourceKind::ExternalScript)
                    .count() as u16,
                inline_scripts: snapshot
                    .resources
                    .iter()
                    .filter(|r| r.kind == ResourceKind::InlineScript)
                    .count() as u16,
                skipped_scripts: snapshot
                    .scripts
                    .iter()
                    .filter(|r| r.status == ScriptStatus::Skipped)
                    .count() as u16,
                script_limit_reached: snapshot.script_limit_reached,
                captured_response_bytes: snapshot.captured_response_bytes,
                requests_made: snapshot.requests_made,
                finished_at: snapshot.finished_at,
            };
            (
                "collected",
                None,
                Some(DbJson(summary)),
                Some(DbJson(snapshot)),
            )
        }
        Err(error) => ("failed", Some(error.0), None, None),
    };
    let updated = sqlx::query("UPDATE site_checks SET state = $3, error = $4, summary = $5, snapshot = $6, evidence_expires_at = CASE WHEN $3 = 'collected' THEN now() + interval '7 days' ELSE NULL END, lease_id = NULL, lease_expires_at = NULL WHERE id = $1 AND lease_id = $2 AND state = 'collecting' AND lease_expires_at > now() AND deadline_at > now()")
        .bind(lease.id).bind(lease.lease_id).bind(state).bind(error).bind(summary).bind(snapshot).execute(pool).await?;
    Ok(updated.rows_affected() == 1)
}

async fn run_once(pool: &PgPool) -> Result<bool, sqlx::Error> {
    let Some(lease) = claim(pool).await? else {
        return Ok(false);
    };
    let collection = collect(&lease.scope.0);
    tokio::pin!(collection);
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            biased;
            _ = interval.tick() => {
                // Stop on lost authority or an unavailable database. Dropping the
                // HTTP future closes our request, but cannot undo an in-flight GET.
                if !current(pool, &lease).await? { return Ok(true); }
            }
            result = &mut collection => {
                finish(pool, &lease, result).await?;
                return Ok(true);
            }
        }
    }
}

/// One cluster-wide collection slot. Leases recover interrupted work at most
/// once; approval expires after ten minutes even across restarts. Stopping this
/// worker cancels current I/O; the persistent lease expires before reassignment.
pub async fn run_worker(pool: PgPool, mut stopping: watch::Receiver<bool>) {
    loop {
        if *stopping.borrow() {
            break;
        }
        let wait = tokio::select! {
            _ = stopping.changed() => break,
            result = run_once(&pool) => match result {
                Ok(true) => Duration::from_millis(100),
                Ok(false) => Duration::from_secs(2),
                Err(_) => { eprintln!("website collection worker unavailable; retrying"); Duration::from_secs(5) },
            }
        };
        tokio::select! {
            _ = stopping.changed() => break,
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

#[cfg(test)]
mod tests;
