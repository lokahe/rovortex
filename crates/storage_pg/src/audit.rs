//! PostgreSQL 审计日志仓储。

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use rovortex_users::audit::{AuditRepository, NewAuditLog};

pub struct PgAuditRepository {
    pool: PgPool,
}

impl PgAuditRepository {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditRepository for PgAuditRepository {
    async fn append(&self, entry: NewAuditLog) -> Result<(), rovortex_users::UserError> {
        sqlx::query!(
            r#"INSERT INTO audit_logs (id, user_id, action, detail, client_ip)
               VALUES ($1, $2, $3, $4, $5)"#,
            Uuid::now_v7(),
            entry.user_id,
            entry.action.as_str(),
            entry.detail,
            entry.client_ip,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| rovortex_users::UserError::Hashing(e.to_string()))?;
        Ok(())
    }
}
