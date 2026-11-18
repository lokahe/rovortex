//! PostgreSQL 版 refresh token 仓储实现。
//!
//! 库中只存 token 的 SHA-256 哈希（领域层传入时已哈希）。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use rovortex_users::{NewRefreshToken, RefreshTokenRepository, UserError};

pub struct PgRefreshTokenRepository {
    pool: PgPool,
}

impl PgRefreshTokenRepository {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn map_err(e: sqlx::Error) -> UserError {
    UserError::Hashing(e.to_string())
}

#[async_trait]
impl RefreshTokenRepository for PgRefreshTokenRepository {
    async fn insert(&self, token: NewRefreshToken) -> Result<(), UserError> {
        sqlx::query!(
            r#"INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at)
               VALUES ($1, $2, $3, $4)"#,
            token.id,
            token.user_id,
            token.token_hash,
            token.expires_at,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn find_active_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<(Uuid, String)>, UserError> {
        let row = sqlx::query!(
            r#"SELECT user_id, token_hash FROM refresh_tokens
               WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()"#,
            token_hash,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| (r.user_id, r.token_hash)))
    }

    async fn revoke_by_hash(&self, token_hash: &str) -> Result<(), UserError> {
        sqlx::query!(
            r#"UPDATE refresh_tokens SET revoked_at = now()
               WHERE token_hash = $1 AND revoked_at IS NULL"#,
            token_hash,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<u64, UserError> {
        let result = sqlx::query!(
            r#"UPDATE refresh_tokens SET revoked_at = now()
               WHERE user_id = $1 AND revoked_at IS NULL"#,
            user_id,
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(result.rows_affected())
    }
}

// 避免未使用导入警告：expires_at 的比较由 SQL 完成。
#[allow(dead_code)]
fn _type_assert(_: DateTime<Utc>) {}
