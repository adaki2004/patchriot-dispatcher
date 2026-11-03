//! Temporary DNS proof for an account's exact, immutable live-test scope.
//! Lookups never run inside a database transaction. The proof grants neither
//! unrestricted testing nor access to other domains. Verified scopes can proceed
//! to requester consent and checkout; staff can still revoke them.
use crate::{Actor, ApiError, AppState, actor};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, Utc};
use hickory_resolver::TokioResolver;
use patchriot_protocol::pentests::{DomainChallenge, LiveScope, OwnershipView, RefreshOwnership};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use std::{future::Future, time::Duration};
use tokio::sync::watch;
use uuid::Uuid;

const PREFIX: &str = "patchriot-domain-verification=";

#[derive(FromRow)]
struct Permission {
    scope_sha256: String,
    state: String,
    expires_at: DateTime<Utc>,
    ownership_verified_at: Option<DateTime<Utc>>,
}

async fn permission(
    tx: &mut Transaction<'_, Postgres>,
    caller: &Actor,
    id: Uuid,
) -> Result<Permission, ApiError> {
    sqlx::query_as("SELECT scope_sha256,state,expires_at,ownership_verified_at FROM pentests WHERE id=$1 AND (requester_id=$2 OR $3) FOR UPDATE")
        .bind(id).bind(caller.id).bind(caller.admin).fetch_optional(&mut **tx).await?.ok_or_else(ApiError::missing)
}

pub(crate) async fn create(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    scope: &LiveScope,
) -> Result<(), ApiError> {
    for origin in &scope.origins {
        let url = url::Url::parse(origin).map_err(|_| ApiError::bad("invalid_origin"))?;
        let domain = url
            .host_str()
            .ok_or_else(|| ApiError::bad("invalid_origin"))?;
        if domain.len() > 243 {
            return Err(ApiError::bad("domain_too_long_for_verification"));
        }
        // Two independent UUIDv4 values carry 244 random bits, not user input.
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        sqlx::query("INSERT INTO domain_challenges(pentest_id,domain,token,expires_at) SELECT id,$2,$3,expires_at FROM pentests WHERE id=$1")
            .bind(id).bind(domain).bind(token).execute(&mut **tx).await?;
    }
    Ok(())
}

#[derive(FromRow)]
struct Challenge {
    pentest_id: Uuid,
    domain: String,
    token: String,
    state: String,
    expires_at: DateTime<Utc>,
    checking_until: Option<DateTime<Utc>>,
    last_checked_at: Option<DateTime<Utc>>,
    verified_at: Option<DateTime<Utc>>,
    error: Option<String>,
}

async fn view(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
    saved: Permission,
) -> Result<OwnershipView, ApiError> {
    let challenges: Vec<Challenge> =
        sqlx::query_as("SELECT * FROM domain_challenges WHERE pentest_id=$1 ORDER BY domain")
            .bind(id)
            .fetch_all(&mut **tx)
            .await?;
    let active = saved.expires_at > Utc::now()
        && matches!(saved.state.as_str(), "pending_approval" | "approved");
    Ok(OwnershipView {
        pentest_id: id,
        scope_sha256: saved.scope_sha256,
        verified: active && saved.ownership_verified_at.is_some(),
        challenges: challenges
            .into_iter()
            .map(|c| DomainChallenge {
                record_name: format!("_patchriot.{}", c.domain),
                record_value: format!("{PREFIX}{}", c.token),
                domain: c.domain,
                state: if !active
                    || c.expires_at <= Utc::now()
                    || (c.state != "verified"
                        && c.checking_until.is_some_and(|until| until <= Utc::now())
                        && c.error.is_none())
                {
                    "expired".into()
                } else {
                    c.state
                },
                expires_at: c.expires_at.timestamp(),
                checking_until: c.checking_until.map(|d| d.timestamp()),
                last_checked_at: c.last_checked_at.map(|d| d.timestamp()),
                verified_at: c.verified_at.map(|d| d.timestamp()),
                error: c.error,
            })
            .collect(),
    })
}

pub(crate) async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<OwnershipView>, ApiError> {
    let caller = actor(&headers, &state)?;
    let mut tx = state.pool.begin().await?;
    let saved = permission(&mut tx, &caller, id).await?;
    let result = view(&mut tx, id, saved).await?;
    tx.commit().await?;
    Ok(Json(result))
}

pub(crate) async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<RefreshOwnership>,
) -> Result<Json<OwnershipView>, ApiError> {
    let caller = actor(&headers, &state)?;
    let mut tx = state.pool.begin().await?;
    let saved = permission(&mut tx, &caller, id).await?;
    if saved.scope_sha256 != input.scope_sha256
        || saved.expires_at <= Utc::now()
        || !matches!(saved.state.as_str(), "pending_approval" | "approved")
    {
        return Err(ApiError::conflict("scope_changed_or_expired"));
    }
    let exhausted: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM domain_challenges WHERE pentest_id=$1 AND state<>'verified' AND windows>=6 AND (checking_until IS NULL OR checking_until<=now()))")
        .bind(id).fetch_one(&mut *tx).await?;
    if exhausted {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "ownership_refresh_limit",
        ));
    }
    // Repeated clicks within a window are idempotent: they cannot prolong it or
    // turn the verifier into an unbounded DNS request generator.
    sqlx::query("UPDATE domain_challenges SET state='pending',error=NULL,checking_until=LEAST(now()+interval '5 minutes',expires_at),next_check_at=now(),windows=windows+1 WHERE pentest_id=$1 AND state<>'verified' AND (checking_until IS NULL OR checking_until<=now())")
        .bind(id).execute(&mut *tx).await?;
    let result = view(&mut tx, id, saved).await?;
    tx.commit().await?;
    Ok(Json(result))
}

/// Injectable DNS transport lets tests exercise the real queue without querying
/// customers' domains or adding a production bypass for ownership checks.
pub trait TxtLookup: Sync {
    fn txt(&self, name: &str) -> impl Future<Output = Result<Vec<Vec<u8>>, &'static str>> + Send;
}

impl TxtLookup for TokioResolver {
    async fn txt(&self, name: &str) -> Result<Vec<Vec<u8>>, &'static str> {
        match self.txt_lookup(name).await {
            Ok(answer) => Ok(txt_records(answer.answers(), name)),
            Err(error) if error.is_no_records_found() || error.is_nx_domain() => Ok(Vec::new()),
            Err(_) => Err("dns_lookup_failed"),
        }
    }
}

fn txt_records(records: &[hickory_resolver::proto::rr::Record], name: &str) -> Vec<Vec<u8>> {
    records
        .iter()
        .filter(|record| record.name.to_ascii().eq_ignore_ascii_case(name))
        .filter_map(|record| match &record.data {
            hickory_resolver::proto::rr::RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .flat_map(|part| part.iter().copied())
                    .collect(),
            ),
            _ => None,
        })
        .collect()
}

/// Process at most eight due records, four at a time. Database reservations and
/// saved deadlines survive restarts; network latency holds no scheduler lock.
pub async fn poll_once(pool: &PgPool, lookup: &impl TxtLookup) -> Result<usize, sqlx::Error> {
    let due: Vec<Challenge> = sqlx::query_as("WITH due AS (SELECT c.pentest_id,c.domain FROM domain_challenges c JOIN pentests p ON p.id=c.pentest_id WHERE c.state<>'verified' AND c.checking_until>now() AND c.expires_at>now() AND c.next_check_at<=now() AND p.state IN ('pending_approval','approved') AND p.expires_at>now() ORDER BY c.next_check_at LIMIT 8 FOR UPDATE OF c SKIP LOCKED) UPDATE domain_challenges c SET next_check_at=now()+interval '30 seconds' FROM due WHERE c.pentest_id=due.pentest_id AND c.domain=due.domain RETURNING c.*")
        .fetch_all(pool).await?;
    let count = due.len();
    // join! bounds concurrency without spawning detached DNS tasks on shutdown.
    for batch in due.chunks(4) {
        let tasks = batch
            .iter()
            .map(|c| check_one(pool, lookup, c))
            .collect::<Vec<_>>();
        let mut tasks = tasks.into_iter();
        let (a, b, c, d) = tokio::join!(
            optional(tasks.next()),
            optional(tasks.next()),
            optional(tasks.next()),
            optional(tasks.next())
        );
        a?;
        b?;
        c?;
        d?;
    }
    Ok(count)
}

async fn optional(
    f: Option<impl Future<Output = Result<(), sqlx::Error>>>,
) -> Result<(), sqlx::Error> {
    if let Some(f) = f { f.await } else { Ok(()) }
}

async fn check_one(
    pool: &PgPool,
    lookup: &impl TxtLookup,
    c: &Challenge,
) -> Result<(), sqlx::Error> {
    // A trailing dot forbids resolver search-domain expansion.
    let name = format!("_patchriot.{}.", c.domain);
    let expected = format!("{PREFIX}{}", c.token);
    let result = tokio::time::timeout(Duration::from_secs(4), lookup.txt(&name)).await;
    let (state, error) = match result {
        Ok(Ok(records)) if records.iter().any(|r| r == expected.as_bytes()) => ("verified", None),
        Ok(Ok(_)) => ("pending", None),
        _ => ("error", Some("dns_lookup_failed")),
    };
    let mut tx = pool.begin().await?;
    // Same lock order as refresh/approval. A late DNS response cannot resurrect
    // a revoked scope, an expired check, or a newer verification window.
    let active: Option<Uuid> = sqlx::query_scalar("SELECT id FROM pentests WHERE id=$1 AND state IN ('pending_approval','approved') AND staff_authorized_at IS NULL AND expires_at>now() FOR UPDATE")
        .bind(c.pentest_id).fetch_optional(&mut *tx).await?;
    if active.is_some() {
        sqlx::query("UPDATE domain_challenges SET state=$3,error=$4,last_checked_at=now(),verified_at=CASE WHEN $3='verified' THEN now() ELSE NULL END WHERE pentest_id=$1 AND domain=$2 AND state<>'verified' AND checking_until=$5 AND checking_until>now() AND expires_at>now()")
            .bind(c.pentest_id).bind(&c.domain).bind(state).bind(error).bind(c.checking_until).execute(&mut *tx).await?;
        // Approve only after every exact origin is verified. Payment, consent and
        // worker eligibility remain separate checks; this creates no work.
        sqlx::query("UPDATE pentests p SET ownership_verified_at=COALESCE(ownership_verified_at,now()),state='approved',expires_at=LEAST(expires_at,now()+interval '24 hours'),decision_note=CASE WHEN state='pending_approval' THEN 'Domain control verified automatically.' ELSE decision_note END WHERE id=$1 AND (SELECT count(*) FROM domain_challenges c WHERE c.pentest_id=p.id)=jsonb_array_length(p.scope->'origins') AND NOT EXISTS(SELECT 1 FROM domain_challenges c WHERE c.pentest_id=p.id AND (c.state<>'verified' OR c.expires_at<=now()))")
            .bind(c.pentest_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE domain_challenges c SET expires_at=LEAST(c.expires_at,p.expires_at) FROM pentests p WHERE c.pentest_id=p.id AND p.id=$1 AND p.ownership_verified_at IS NOT NULL")
            .bind(c.pentest_id).execute(&mut *tx).await?;
    }
    tx.commit().await
}

pub async fn run_worker(pool: PgPool, lookup: TokioResolver, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => return,
            result = poll_once(&pool, &lookup) => if result.is_err() { eprintln!("domain verification database operation failed"); },
        }
        tokio::select! { _ = stop.changed() => return, _ = tokio::time::sleep(Duration::from_secs(5)) => {} }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::{Name, RData, Record, rdata::TXT};

    #[test]
    fn txt_fragments_join_only_within_one_record_at_the_exact_name() {
        let name = Name::from_ascii("_patchriot.example.com.").unwrap();
        let records = vec![
            Record::from_rdata(
                name.clone(),
                60,
                RData::TXT(TXT::new(vec![
                    "patchriot-domain-".into(),
                    "verification=value".into(),
                ])),
            ),
            Record::from_rdata(
                Name::from_ascii("unrelated.example.com.").unwrap(),
                60,
                RData::TXT(TXT::new(vec!["wrong-owner".into()])),
            ),
            Record::from_rdata(
                name,
                60,
                RData::TXT(TXT::new(vec!["different-record".into()])),
            ),
        ];
        assert_eq!(
            txt_records(&records, "_PATCHRIOT.example.com."),
            vec![
                b"patchriot-domain-verification=value".to_vec(),
                b"different-record".to_vec()
            ]
        );
        assert!(txt_records(&records, "_patchriot.other.com.").is_empty());
    }
}
