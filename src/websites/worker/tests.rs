use super::*;
use patchriot_protocol::websites::WebsiteResource;
use sqlx::postgres::PgPoolOptions;
use std::collections::BTreeMap;

struct Database {
    pool: PgPool,
    admin: PgPool,
    schema: String,
}

impl Database {
    async fn new() -> Self {
        let url =
            std::env::var("PATCHRIOT_TEST_DATABASE_URL").expect("local test database required");
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let schema = format!("test_collection_{}", Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {schema}")))
            .execute(&admin)
            .await
            .unwrap();
        let search = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .after_connect(move |c, _| {
                let search = search.clone();
                Box::pin(async move {
                    sqlx::query("SELECT set_config('search_path',$1,false)")
                        .bind(search)
                        .execute(c)
                        .await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        Self {
            pool,
            admin,
            schema,
        }
    }

    async fn queued(&self) -> Uuid {
        let id = Uuid::new_v4();
        let scope = WebsiteScope {
            homepage: "https://example.com/".into(),
            script_origins: vec![],
        };
        sqlx::query("INSERT INTO site_checks (id,request_id,requester_id,scope,scope_sha256,authority_note,state,deadline_at) VALUES ($1,$2,$3,$4,$5,'Owned worker fixture','queued',now() + interval '10 minutes')")
            .bind(id).bind(Uuid::new_v4()).bind(Uuid::new_v4()).bind(DbJson(scope)).bind("0".repeat(64)).execute(&self.pool).await.unwrap();
        id
    }

    async fn close(self) {
        self.pool.close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP SCHEMA {} CASCADE",
            self.schema
        )))
        .execute(&self.admin)
        .await
        .unwrap();
        self.admin.close().await;
    }
}

fn snapshot(lease: &CollectionLease) -> WebsiteSnapshot {
    WebsiteSnapshot {
        schema_version: 1,
        scope: lease.scope.0.clone(),
        homepage: WebsiteResource {
            kind: ResourceKind::Homepage,
            url: lease.scope.0.homepage.clone(),
            sha256: "0".repeat(64),
            bytes: 5,
            content_type: "text/html".into(),
            headers: BTreeMap::new(),
            text: "owned".into(),
            collected_at: crate::now(),
            connected_ip: None,
        },
        resources: vec![],
        scripts: vec![],
        script_limit_reached: false,
        requests_made: 1,
        captured_response_bytes: 5,
        started_at: crate::now(),
        finished_at: crate::now(),
    }
}

#[tokio::test]
async fn concurrent_workers_share_one_slot_and_cancelled_work_cannot_publish() {
    let db = Database::new().await;
    db.queued().await;
    db.queued().await;
    let (a, b) = tokio::join!(claim(&db.pool), claim(&db.pool));
    let leases: Vec<_> = [a.unwrap(), b.unwrap()].into_iter().flatten().collect();
    assert_eq!(leases.len(), 1);
    let lease = &leases[0];
    assert!(current(&db.pool, lease).await.unwrap());
    sqlx::query(
        "UPDATE site_checks SET state='cancelled',lease_id=NULL,lease_expires_at=NULL WHERE id=$1",
    )
    .bind(lease.id)
    .execute(&db.pool)
    .await
    .unwrap();
    assert!(!current(&db.pool, lease).await.unwrap());
    assert!(!finish(&db.pool, lease, Ok(snapshot(lease))).await.unwrap());
    let replacement = claim(&db.pool).await.unwrap().unwrap();
    assert_ne!(replacement.id, lease.id);
    assert!(
        finish(&db.pool, &replacement, Ok(snapshot(&replacement)))
            .await
            .unwrap()
    );
    assert!(
        !finish(&db.pool, &replacement, Ok(snapshot(&replacement)))
            .await
            .unwrap()
    );
    let (state, retained): (String, bool) =
        sqlx::query_as("SELECT state,snapshot IS NOT NULL FROM site_checks WHERE id=$1")
            .bind(lease.id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!((state.as_str(), retained), ("cancelled", false));
    let (state, available): (String,bool) = sqlx::query_as("SELECT state,snapshot IS NOT NULL AND evidence_expires_at > now() FROM site_checks WHERE id=$1").bind(replacement.id).fetch_one(&db.pool).await.unwrap();
    assert_eq!((state.as_str(), available), ("collected", true));
    db.close().await;
}

#[tokio::test]
async fn interruption_retries_once_without_extending_approval_or_accepting_old_results() {
    let db = Database::new().await;
    let id = db.queued().await;
    let deadline: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT deadline_at FROM site_checks WHERE id=$1")
            .bind(id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    let first = claim(&db.pool).await.unwrap().unwrap();
    sqlx::query("UPDATE site_checks SET lease_expires_at=now()-interval '1 second' WHERE id=$1")
        .bind(id)
        .execute(&db.pool)
        .await
        .unwrap();
    let second = claim(&db.pool).await.unwrap().unwrap();
    assert_eq!(first.id, second.id);
    assert_ne!(first.lease_id, second.lease_id);
    assert!(!current(&db.pool, &first).await.unwrap());
    assert!(
        !finish(&db.pool, &first, Ok(snapshot(&first)))
            .await
            .unwrap()
    );
    sqlx::query("UPDATE site_checks SET lease_expires_at=now()-interval '1 second' WHERE id=$1")
        .bind(id)
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(claim(&db.pool).await.unwrap().is_none());
    assert!(
        !finish(&db.pool, &second, Ok(snapshot(&second)))
            .await
            .unwrap()
    );
    let (state, attempts, after): (String, i32, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT state,attempts,deadline_at FROM site_checks WHERE id=$1")
            .bind(id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(state, "failed");
    assert_eq!(attempts, 2);
    assert_eq!(after, deadline);
    db.close().await;
}

#[tokio::test]
async fn expiry_or_mismatched_evidence_cannot_complete_a_scope() {
    let db = Database::new().await;
    let id = db.queued().await;
    let lease = claim(&db.pool).await.unwrap().unwrap();
    sqlx::query("UPDATE site_checks SET deadline_at=now()-interval '1 second' WHERE id=$1")
        .bind(id)
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(!current(&db.pool, &lease).await.unwrap());
    assert!(
        !finish(&db.pool, &lease, Ok(snapshot(&lease)))
            .await
            .unwrap()
    );
    assert!(claim(&db.pool).await.unwrap().is_none());
    let id = db.queued().await;
    let lease = claim(&db.pool).await.unwrap().unwrap();
    let mut wrong = snapshot(&lease);
    wrong.scope.homepage = "https://different.example/".into();
    assert!(finish(&db.pool, &lease, Ok(wrong)).await.unwrap());
    let (state, error, retained): (String, String, bool) =
        sqlx::query_as("SELECT state,error,snapshot IS NOT NULL FROM site_checks WHERE id=$1")
            .bind(id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(state, "failed");
    assert_eq!(error, "snapshot_scope_mismatch");
    assert!(!retained);
    db.close().await;
}
