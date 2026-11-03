//! Optional, requester-consented report advice. The original findings and work
//! outcome never change. Signature verification authenticates bytes, not claims.
mod provider;
#[cfg(test)]
mod tests;

use crate::{ApiError, AppState, actor};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, Utc};
use patchriot_protocol::WorkResult;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, types::Json as DbJson};
use std::{collections::HashSet, time::Duration};
use tokio::sync::watch;
use uuid::Uuid;

pub use provider::NearCheck;
pub const MODEL: &str = "Qwen/Qwen3.8-27B-abliterated";
const MAX_FINDINGS: usize = 48;
const MAX_INPUT_BYTES: usize = 48 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consent {
    accepts_near_ai: bool,
}

#[derive(sqlx::FromRow)]
struct ReportContext {
    state: String,
    mode: String,
    pentest_context: Option<DbJson<Value>>,
    report_expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Advice {
    duplicate_groups: Vec<Vec<String>>,
    review_ids: Vec<String>,
    explanation: String,
}

fn text(value: &str, maximum: usize) -> String {
    let mut bounded: String = value.chars().take(maximum).collect();
    if value.chars().count() > maximum {
        bounded.push_str(" [excerpt]");
    }
    bounded
}

fn finding_input(
    id: Uuid,
    scope_hash: &str,
    parts: &[(String, DbJson<WorkResult>)],
) -> Result<Value, &'static str> {
    let mut findings = Vec::new();
    let mut omitted = 0;
    for (role, result) in parts {
        let WorkResult::Pentest(result) = &result.0 else {
            continue;
        };
        let Some(assessment) = &result.assessment else {
            continue;
        };
        for (index, finding) in assessment.findings.iter().enumerate() {
            if findings.len() >= MAX_FINDINGS {
                omitted += 1;
                continue;
            }
            let references: Vec<_> = finding.evidence_ids.iter().take(4).filter_map(|id| {
                result.evidence.iter().find(|e| e.id == *id).map(|e| {
                    // No raw HTTP bodies, query values, headers, cookies or credentials.
                    let path = url::Url::parse(&e.url).ok().map(|u| format!("{}{}", u.origin().ascii_serialization(), u.path()));
                    let context = hex::encode(Sha256::digest(json!([e.method,e.url,e.authenticated,e.request_body_sha256]).to_string().as_bytes()));
                    json!({"id":e.id,"method":e.method,"url_without_query":path,"status":e.status,"authenticated":e.authenticated,"request_context_sha256":context})
                })
            }).collect();
            findings.push(json!({"id":format!("{role}-{}", index + 1),"role":role,"title":text(&finding.title, 200),"severity":finding.severity,"support":finding.support,"explanation":text(&finding.explanation, 650),"reproduction":text(&finding.reproduction, 350),"references":references}));
        }
    }
    if findings.is_empty() {
        return Err("no_findings_to_check");
    }
    let input = json!({"schema_version":1,"review_id":id,"scope_sha256":scope_hash,"findings":findings,"omitted_findings":omitted});
    if serde_json::to_vec(&input)
        .map_err(|_| "report_check_encoding_failed")?
        .len()
        > MAX_INPUT_BYTES
    {
        return Err("report_check_summary_too_large");
    }
    Ok(input)
}

pub(super) fn validate_advice(value: Value, input: &Value) -> Result<Advice, &'static str> {
    let advice: Advice =
        serde_json::from_value(value).map_err(|_| "report_check_output_invalid")?;
    let allowed: HashSet<_> = input["findings"]
        .as_array()
        .ok_or("report_check_input_invalid")?
        .iter()
        .filter_map(|v| v["id"].as_str())
        .collect();
    let mut grouped = HashSet::new();
    if advice.duplicate_groups.len() > 12
        || advice.review_ids.len() > MAX_FINDINGS
        || advice.explanation.is_empty()
        || advice.explanation.chars().count() > 1800
    {
        return Err("report_check_output_invalid");
    }
    for group in &advice.duplicate_groups {
        if !(2..=6).contains(&group.len())
            || group
                .iter()
                .any(|id| !allowed.contains(id.as_str()) || !grouped.insert(id.as_str()))
        {
            return Err("report_check_output_invalid");
        }
    }
    let mut reviewed = HashSet::new();
    if advice
        .review_ids
        .iter()
        .any(|id| !allowed.contains(id.as_str()) || !reviewed.insert(id))
    {
        return Err("report_check_output_invalid");
    }
    Ok(advice)
}

pub(crate) async fn get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Value>, ApiError> {
    let caller = actor(&headers, &state)?;
    let owner: Option<(Uuid, Option<DateTime<Utc>>, bool)> = sqlx::query_as("SELECT requester_id,report_expires_at,mode='pentest_agent' AND state IN ('completed','needs_review') AND EXISTS(SELECT 1 FROM review_steps s WHERE s.review_id=reviews.id AND jsonb_array_length(COALESCE(s.result->'assessment'->'findings','[]'::jsonb))>0) FROM reviews WHERE id=$1 AND (requester_id=$2 OR $3)")
        .bind(id).bind(caller.id).bind(caller.admin).fetch_optional(&state.pool).await?;
    let (requester, expires, finished) = owner.ok_or_else(ApiError::missing)?;
    if expires.is_some_and(|e| e <= Utc::now()) {
        return Ok(Json(
            json!({"state":"deleted","model":MODEL,"can_request":false}),
        ));
    }
    let record: Option<(String, Option<DbJson<Value>>, Option<String>)> = sqlx::query_as(
        "SELECT state,result,error_code FROM report_consistency_checks WHERE review_id=$1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;
    if expires.is_some_and(|e| e <= Utc::now()) {
        return Ok(Json(
            json!({"state":"deleted","model":MODEL,"can_request":false}),
        ));
    }
    Ok(Json(match record {
        Some((status, result, error)) => {
            json!({"state":status,"model":MODEL,"can_request":false,"result":result.map(|v| v.0),"error_code":error})
        }
        None => {
            json!({"state":"not_requested","model":MODEL,"can_request":finished && requester==caller.id && state.near_check.is_some()})
        }
    }))
}

pub(crate) async fn request(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(consent): Json<Consent>,
) -> Result<Json<Value>, ApiError> {
    let caller = actor(&headers, &state)?;
    if !consent.accepts_near_ai {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "near_ai_consent_required",
        ));
    }
    let mut tx = state.pool.begin().await?;
    crate::reviews::scheduler(&mut tx).await?;
    let review: Option<ReportContext> = sqlx::query_as("SELECT state,mode,pentest_context,report_expires_at FROM reviews WHERE id=$1 AND requester_id=$2 FOR UPDATE")
        .bind(id).bind(caller.id).fetch_optional(&mut *tx).await?;
    let ReportContext {
        state: status,
        mode,
        pentest_context: context,
        report_expires_at: expires,
    } = review.ok_or_else(ApiError::missing)?;
    if expires.is_some_and(|e| e <= Utc::now()) {
        return Err(ApiError::new(StatusCode::GONE, "report_content_deleted"));
    }
    if mode != "pentest_agent" || !matches!(status.as_str(), "completed" | "needs_review") {
        return Err(ApiError::conflict("report_not_finished"));
    }
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM report_consistency_checks WHERE review_id=$1)",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if !exists {
        if state.near_check.is_none() {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "near_ai_not_configured",
            ));
        }
        if expires.is_some_and(|e| e <= Utc::now() + chrono::Duration::minutes(4)) {
            return Err(ApiError::conflict("report_expires_too_soon"));
        }
        let parts: Vec<(String, DbJson<WorkResult>)> = sqlx::query_as("SELECT role,result FROM review_steps WHERE review_id=$1 AND result IS NOT NULL ORDER BY position").bind(id).fetch_all(&mut *tx).await?;
        let context = context.ok_or_else(|| ApiError::conflict("report_scope_unavailable"))?;
        let input = finding_input(
            id,
            context.0["scope_sha256"]
                .as_str()
                .ok_or_else(|| ApiError::conflict("report_scope_unavailable"))?,
            &parts,
        )
        .map_err(ApiError::conflict)?;
        let digest = hex::encode(Sha256::digest(serde_json::to_vec(&input)?));
        sqlx::query("INSERT INTO report_consistency_checks(review_id,state,input,input_sha256) VALUES($1,'queued',$2,$3)").bind(id).bind(DbJson(input)).bind(digest).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    get(State(state), headers, Path(id)).await
}

#[derive(sqlx::FromRow)]
pub(super) struct Claim {
    review_id: Uuid,
    claim_id: Uuid,
    input: DbJson<Value>,
}

async fn claim(pool: &PgPool) -> Result<Option<Claim>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(72638120)")
        .execute(&mut *tx)
        .await?;
    // Never repeat inference after a crash or unknown outcome.
    sqlx::query("UPDATE report_consistency_checks SET state='unavailable',error_code='check_interrupted',claim_id=NULL,claim_until=NULL WHERE state='running' AND claim_until<=now()").execute(&mut *tx).await?;
    sqlx::query("UPDATE report_consistency_checks c SET state='unavailable',input=NULL,error_code='report_expires_too_soon' FROM reviews r WHERE r.id=c.review_id AND c.state='queued' AND r.report_expires_at<=now()+interval '4 minutes'").execute(&mut *tx).await?;
    let result = sqlx::query_as("UPDATE report_consistency_checks SET state='running',claim_id=$1,claim_until=now()+interval '4 minutes' WHERE review_id=(SELECT c.review_id FROM report_consistency_checks c JOIN reviews r ON r.id=c.review_id WHERE c.state='queued' AND (r.report_expires_at IS NULL OR r.report_expires_at>now()+interval '4 minutes') AND NOT EXISTS(SELECT 1 FROM report_consistency_checks WHERE state='running') ORDER BY c.requested_at FOR UPDATE OF c SKIP LOCKED LIMIT 1) RETURNING review_id,claim_id,input")
        .bind(Uuid::new_v4()).fetch_optional(&mut *tx).await?;
    tx.commit().await?;
    Ok(result)
}

async fn finish(
    pool: &PgPool,
    claim: &Claim,
    result: Result<Value, &'static str>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(72638102)")
        .execute(&mut *tx)
        .await?;
    // Serialize with first export and content deletion. Late completion cannot
    // recreate a report after its retention clock has expired.
    let live: bool = sqlx::query_scalar("SELECT report_expires_at IS NULL OR report_expires_at>now() FROM reviews WHERE id=$1 FOR UPDATE").bind(claim.review_id).fetch_one(&mut *tx).await?;
    if live {
        let (status, value, code) = match result {
            Ok(v) => ("verified", Some(DbJson(v)), None),
            Err(code) => ("unavailable", None, Some(code)),
        };
        sqlx::query("UPDATE report_consistency_checks SET state=$3,result=$4,error_code=$5,input=NULL,checked_at=now(),claim_id=NULL,claim_until=NULL WHERE review_id=$1 AND claim_id=$2 AND state='running' AND claim_until>now()")
            .bind(claim.review_id).bind(claim.claim_id).bind(status).bind(value).bind(code).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn run_worker(
    pool: PgPool,
    checker: Option<NearCheck>,
    mut stopped: watch::Receiver<bool>,
) {
    let Some(checker) = checker else { return };
    let mut timer = tokio::time::interval(Duration::from_secs(5));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        if *stopped.borrow() {
            break;
        }
        tokio::select! {
            _ = stopped.changed() => break,
            _ = timer.tick() => {
                let work = async {
                    if let Some(claim) = claim(&pool).await? {
                        let result = checker.check(&claim.input).await;
                        finish(&pool, &claim, result).await?;
                    }
                    Ok::<_,sqlx::Error>(())
                };
                tokio::select! {
                    _ = stopped.changed() => break,
                    result = work => { if result.is_err() { eprintln!("report consistency check storage unavailable"); } }
                }
            }
        }
    }
}
