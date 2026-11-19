//! PostgreSQL 版邮箱验证仓储。

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use rovortex_users::{
    EmailVerificationRepository, NewEmailVerification, UserError, VerificationPurpose,
};

pub struct PgEmailVerificationRepository {
    pool: PgPool,
}

impl PgEmailVerificationRepository {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn map_err(e: sqlx::Error) -> UserError {
    UserError::Hashing(e.to_string())
}

#[async_trait]
impl EmailVerificationRepository for PgEmailVerificationRepository {
    async fn insert(&self, v: NewEmailVerification) -> Result<(), UserError> {
        sqlx::query!(
            r#"INSERT INTO email_verifications (id, email, token_hash, purpose, user_id, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
            v.id,
            v.email,
            v.token_hash,
            v.purpose.as_str(),
            v.user_id,
            v.expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn consume_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<(String, VerificationPurpose, Option<Uuid>)>, UserError> {
        // 原子消费：UPDATE ... WHERE 未消费未过期 RETURNING，天然防重放。
        let row = sqlx::query!(
            r#"UPDATE email_verifications SET consumed_at = now()
               WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
               RETURNING email, purpose, user_id"#,
            token_hash,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;

        Ok(row.map(|r| {
            let purpose = match r.purpose.as_str() {
                "email_change" => VerificationPurpose::EmailChange,
                "magic_link" => VerificationPurpose::MagicLink,
                "password_reset" => VerificationPurpose::PasswordReset,
                "account_deletion" => VerificationPurpose::AccountDeletion,
                "account_recovery" => VerificationPurpose::AccountRecovery,
                _ => VerificationPurpose::Signup,
            };
            (r.email, purpose, r.user_id)
        }))
    }
}
