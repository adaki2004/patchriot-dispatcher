//! Private source intake. We store bounded UTF-8 JSON, never unpack or execute it.
use crate::{Actor, ApiError, AppState, actor, reviews};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use chrono::{DateTime, Utc};
use patchriot_protocol::{CancelReview, sources::*};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Transaction, types::Json as DbJson};
use uuid::Uuid;

#[derive(FromRow)]
struct Row {
    id: Uuid,
    requester_id: Uuid,
    request_id: Uuid,
    title: String,
    objective: String,
    permission_note: String,
    state: String,
    bundle_sha256: String,
    manifest: DbJson<Vec<SourceFileInfo>>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    decision_note: Option<String>,
}
impl Row {
    fn view(self, caller: &Actor) -> SourceUploadView {
        SourceUploadView {
            id: self.id,
            request_id: self.request_id,
            title: self.title,
            objective: self.objective,
            permission_note: self.permission_note,
            state: self.state,
            bundle_sha256: self.bundle_sha256,
            files: self.manifest.0,
            created_at: self.created_at.timestamp(),
            expires_at: self.expires_at.timestamp(),
            decision_note: self.decision_note,
            can_delete: self.requester_id == caller.id,
        }
    }
}

pub(crate) async fn sweep(tx: &mut Transaction<'_, Postgres>) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE source_uploads SET state = 'expired', bundle = NULL WHERE bundle IS NOT NULL AND expires_at <= now()")
        .execute(&mut **tx).await?;
    Ok(())
}

async fn read(pool: &PgPool, caller: &Actor, id: Uuid) -> Result<SourceUploadView, ApiError> {
    let row: Row = sqlx::query_as("SELECT id,requester_id,request_id,title,objective,permission_note,state,bundle_sha256,manifest,created_at,expires_at,decision_note FROM source_uploads WHERE id = $1 AND (requester_id = $2 OR $3)")
        .bind(id).bind(caller.id).bind(caller.admin).fetch_optional(pool).await?.ok_or_else(ApiError::missing)?;
    Ok(row.view(caller))
}

pub(crate) async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SourceUploadView>>, ApiError> {
    let caller = actor(&headers, &state)?;
    reviews::expire(&state.pool).await?;
    let rows: Vec<Row> = sqlx::query_as("SELECT id,requester_id,request_id,title,objective,permission_note,state,bundle_sha256,manifest,created_at,expires_at,decision_note FROM source_uploads WHERE requester_id = $1 OR $2 ORDER BY created_at DESC LIMIT 50")
        .bind(caller.id).bind(caller.admin).fetch_all(&state.pool).await?;
    Ok(Json(rows.into_iter().map(|r| r.view(&caller)).collect()))
}

pub(crate) async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<SourceUploadView>, ApiError> {
    let caller = actor(&headers, &state)?;
    reviews::expire(&state.pool).await?;
    Ok(Json(read(&state.pool, &caller, id).await?))
}

pub(crate) async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CreateSourceUpload>,
) -> Result<Json<SourceUploadView>, ApiError> {
    let caller = actor(&headers, &state)?;
    let bundle = input.bundle().map_err(ApiError::bad)?;
    let digest = bundle_hash(&bundle)?;
    // Sorted files make retries independent of a file picker's ordering. Notes
    // and the objective remain part of this immutable request identity.
    let request_hash = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(
            &input.title,
            &input.permission_note,
            &bundle
        ))?)
    );
    let mut tx = state.pool.begin().await?;
    reviews::scheduler(&mut tx).await?;
    reviews::sweep(&mut tx).await?;
    let existing: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT id,request_sha256 FROM source_uploads WHERE requester_id = $1 AND request_id = $2",
    )
    .bind(caller.id)
    .bind(input.request_id)
    .fetch_optional(&mut *tx)
    .await?;
    let id = if let Some((id, hash)) = existing {
        if hash != request_hash {
            return Err(ApiError::conflict("conflicting_source_request"));
        }
        id
    } else {
        // Bounds include deleted/rejected uploads so deletion cannot reset the
        // intake rate. The global scheduler lock makes counts atomic.
        let (recent, retained, total): (i64,i64,i64) = sqlx::query_as("SELECT count(*) FILTER (WHERE requester_id = $1 AND created_at > now() - interval '24 hours'), count(*) FILTER (WHERE requester_id = $1 AND bundle IS NOT NULL), count(*) FILTER (WHERE bundle IS NOT NULL) FROM source_uploads")
            .bind(caller.id).fetch_one(&mut *tx).await?;
        if recent >= 20 || retained >= 5 || total >= 200 {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "source_upload_limit",
            ));
        }
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO source_uploads (id,requester_id,request_id,request_sha256,title,objective,permission_note,bundle_sha256,manifest,bundle) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
            .bind(id).bind(caller.id).bind(input.request_id).bind(request_hash).bind(&input.title).bind(&input.objective).bind(&input.permission_note).bind(digest).bind(DbJson(bundle.manifest())).bind(DbJson(bundle)).execute(&mut *tx).await?;
        id
    };
    tx.commit().await?;
    Ok(Json(read(&state.pool, &caller, id).await?))
}

pub(crate) async fn decide(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<DecideSourceUpload>,
) -> Result<Json<SourceUploadView>, ApiError> {
    let caller = actor(&headers, &state)?;
    if !caller.admin {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "admin_required"));
    }
    if input.note.trim().len() < 8
        || input.note.len() > 1200
        || input.note.chars().any(char::is_control)
    {
        return Err(ApiError::bad("decision_note_required"));
    }
    let mut tx = state.pool.begin().await?;
    reviews::scheduler(&mut tx).await?;
    reviews::sweep(&mut tx).await?;
    let current: (String, Option<String>) =
        sqlx::query_as("SELECT state,decision_note FROM source_uploads WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(ApiError::missing)?;
    let desired = if input.approve {
        "approved"
    } else {
        "rejected"
    };
    if current.0 == "pending_approval" {
        sqlx::query("UPDATE source_uploads SET state = $2, bundle = CASE WHEN $2 = 'approved' THEN bundle ELSE NULL END, decided_by = $3, decision_note = $4, decided_at = now() WHERE id = $1")
            .bind(id).bind(desired).bind(caller.id).bind(&input.note).execute(&mut *tx).await?;
    } else if current.0 != desired || current.1.as_deref() != Some(&input.note) {
        return Err(ApiError::conflict("source_already_decided"));
    }
    tx.commit().await?;
    Ok(Json(read(&state.pool, &caller, id).await?))
}

pub(crate) async fn delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(_): Json<CancelReview>,
) -> Result<Json<SourceUploadView>, ApiError> {
    let caller = actor(&headers, &state)?;
    let mut tx = state.pool.begin().await?;
    reviews::scheduler(&mut tx).await?;
    let changed = sqlx::query("UPDATE source_uploads SET state = 'deleted', bundle = NULL WHERE id = $1 AND requester_id = $2")
        .bind(id).bind(caller.id).execute(&mut *tx).await?.rows_affected();
    if changed == 0 {
        return Err(ApiError::missing());
    }
    sqlx::query("UPDATE reviews SET state = 'cancelled' WHERE source_id = $1 AND state IN ('awaiting_payment','queued','running')")
        .bind(id).execute(&mut *tx).await?;
    reviews::sweep(&mut tx).await?;
    tx.commit().await?;
    Ok(Json(read(&state.pool, &caller, id).await?))
}

pub(crate) async fn artifact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<SourceBundle>, ApiError> {
    let caller = actor(&headers, &state)?;
    reviews::expire(&state.pool).await?;
    let bundle: DbJson<SourceBundle> = sqlx::query_scalar("SELECT bundle FROM source_uploads WHERE id = $1 AND (requester_id = $2 OR $3) AND bundle IS NOT NULL AND expires_at > now()")
        .bind(id).bind(caller.id).bind(caller.admin).fetch_optional(&state.pool).await?.ok_or_else(ApiError::missing)?;
    Ok(Json(bundle.0))
}
