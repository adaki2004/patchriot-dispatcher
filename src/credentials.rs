//! Short-lived test accounts. The database contains authenticated ciphertext;
//! only the assigned, approved device's active lease can read the plaintext.
use crate::{ApiError, AppState};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use axum::http::StatusCode;
use patchriot_protocol::pentests::TestCredentials;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) struct Vault(Zeroizing<[u8; 32]>);
impl Vault {
    pub fn from_hex(value: &str) -> Result<Self, &'static str> {
        let mut key = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(value, &mut *key)
            .map_err(|_| "credential key must be 32 random bytes encoded as hex")?;
        if key.iter().all(|b| *b == 0) {
            return Err("credential key cannot be zero");
        }
        Ok(Self(key))
    }
    pub(crate) fn seal(&self, aad: &[u8], input: &TestCredentials) -> Result<Vec<u8>, ApiError> {
        let mut bytes = [0u8; 12];
        getrandom::fill(&mut bytes).map_err(|_| unavailable())?;
        let plaintext = Zeroizing::new(serde_json::to_vec(input)?);
        let cipher = Aes256Gcm::new_from_slice(&*self.0).map_err(|_| unavailable())?;
        let encrypted = cipher
            .encrypt(
                &Nonce::from(bytes),
                Payload {
                    msg: &plaintext,
                    aad,
                },
            )
            .map_err(|_| unavailable())?;
        Ok([bytes.as_slice(), encrypted.as_slice()].concat())
    }
    pub(crate) fn open(&self, aad: &[u8], data: &[u8]) -> Result<TestCredentials, ApiError> {
        if !(28..=8192).contains(&data.len()) {
            return Err(unavailable());
        }
        let bytes: [u8; 12] = data[..12].try_into().map_err(|_| unavailable())?;
        let cipher = Aes256Gcm::new_from_slice(&*self.0).map_err(|_| unavailable())?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &Nonce::from(bytes),
                    Payload {
                        msg: &data[12..],
                        aad,
                    },
                )
                .map_err(|_| unavailable())?,
        );
        let input: TestCredentials =
            serde_json::from_slice(&plaintext).map_err(|_| unavailable())?;
        if !input.valid() {
            return Err(unavailable());
        }
        Ok(input)
    }
}
fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "test_credentials_unavailable",
    )
}
fn binding(id: Uuid, account: Uuid, hash: &str) -> Vec<u8> {
    format!("patchriot.test-credentials.v1:{id}:{account}:{hash}").into_bytes()
}
pub(crate) async fn save(
    tx: &mut Transaction<'_, Postgres>,
    state: &AppState,
    id: Uuid,
    account: Uuid,
    hash: &str,
    input: &TestCredentials,
) -> Result<(), ApiError> {
    let vault = state.credential_vault.as_ref().ok_or_else(unavailable)?;
    let bytes = vault.seal(&binding(id, account, hash), input)?;
    sqlx::query("INSERT INTO pentest_credentials(pentest_id,ciphertext,expires_at) SELECT id,$2,LEAST(expires_at,now()+interval '24 hours') FROM pentests WHERE id=$1 ON CONFLICT(pentest_id) DO UPDATE SET ciphertext=EXCLUDED.ciphertext,expires_at=EXCLUDED.expires_at")
        .bind(id).bind(bytes).execute(&mut **tx).await?;
    Ok(())
}
pub(crate) async fn read(
    tx: &mut Transaction<'_, Postgres>,
    state: &AppState,
    id: Uuid,
) -> Result<TestCredentials, ApiError> {
    let row: Option<(Uuid,String,Vec<u8>)> = sqlx::query_as("SELECT p.requester_id,p.scope_sha256,c.ciphertext FROM pentest_credentials c JOIN pentests p ON p.id=c.pentest_id WHERE p.id=$1 AND c.expires_at>now() AND p.expires_at>now() AND p.state IN ('pending_approval','approved')")
        .bind(id).fetch_optional(&mut **tx).await?;
    let (account, hash, bytes) = row.ok_or_else(unavailable)?;
    state
        .credential_vault
        .as_ref()
        .ok_or_else(unavailable)?
        .open(&binding(id, account, &hash), &bytes)
}
pub(crate) async fn require(
    tx: &mut Transaction<'_, Postgres>,
    state: &AppState,
    id: Uuid,
    authenticated: bool,
) -> Result<(), ApiError> {
    if !authenticated {
        return Ok(());
    }
    read(tx, state, id).await?;
    Ok(())
}
pub(crate) async fn sweep(tx: &mut Transaction<'_, Postgres>) -> Result<(), ApiError> {
    // A credential set is single-assessment. Never resurrect it by retrying a
    // cancelled or completed request. A new test needs fresh scope and consent.
    sqlx::query("DELETE FROM pentest_credentials c USING pentests p WHERE c.pentest_id=p.id AND (c.expires_at<=now() OR p.expires_at<=now() OR p.state IN ('rejected','revoked','expired') OR EXISTS (SELECT 1 FROM reviews r WHERE r.pentest_id=p.id AND r.state IN ('completed','needs_review','failed','cancelled')))")
        .execute(&mut **tx).await?;
    sqlx::query("UPDATE pentest_preparations x SET gate_ciphertext=NULL WHERE gate_ciphertext IS NOT NULL AND (expires_at<=now() OR EXISTS(SELECT 1 FROM pentests p WHERE p.id=x.pentest_id AND (p.expires_at<=now() OR p.state IN ('rejected','revoked','expired'))) OR EXISTS(SELECT 1 FROM reviews r WHERE r.request_id=x.request_id AND r.requester_id=x.requester_id AND r.state IN ('completed','needs_review','failed','cancelled')))")
        .execute(&mut **tx).await?;
    Ok(())
}

/// Delete expired/finished secrets even when no devices are polling.
pub async fn run_cleanup(pool: sqlx::PgPool, mut stopped: tokio::sync::watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tokio::select! {
            _=interval.tick()=> { if crate::reviews::expire(&pool).await.is_err() { eprintln!("assessment cleanup unavailable; will retry"); } },
            changed=stopped.changed()=> { if changed.is_err() || *stopped.borrow() { break; } }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ciphertext_binds_account_scope_and_target_and_detects_tampering() {
        let vault = Vault::from_hex(&"1a".repeat(32)).unwrap();
        let account = Uuid::new_v4();
        let id = Uuid::new_v4();
        let aad = binding(id, account, "scope-hash");
        let input = TestCredentials::Bearer {
            token: "synthetic-token-not-valid-anywhere".into(),
        };
        let sealed = vault.seal(&aad, &input).ok().unwrap();
        assert!(!String::from_utf8_lossy(&sealed).contains("synthetic-token"));
        assert_ne!(sealed, vault.seal(&aad, &input).ok().unwrap());
        assert_eq!(vault.open(&aad, &sealed).ok().unwrap(), input);
        for bad in [
            binding(Uuid::new_v4(), account, "scope-hash"),
            binding(id, Uuid::new_v4(), "scope-hash"),
            binding(id, account, "other-scope"),
        ] {
            assert!(vault.open(&bad, &sealed).is_err());
        }
        let mut changed = sealed;
        changed[20] ^= 1;
        assert!(vault.open(&aad, &changed).is_err());
        assert!(Vault::from_hex(&"00".repeat(32)).is_err());
    }
}
