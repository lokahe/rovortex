//! PostgreSQL 审计日志仓储。

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use rovortex_users::audit::{AuditEntry, AuditRepository, NewAuditLog};

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

    async fn list_for_user(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<AuditEntry>, rovortex_users::UserError> {
        let rows = sqlx::query!(
            r#"SELECT action, detail, client_ip, created_at
               FROM audit_logs WHERE user_id = $1
               ORDER BY created_at DESC LIMIT $2"#,
            user_id,
            limit,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| rovortex_users::UserError::Hashing(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| AuditEntry {
                action: r.action,
                detail: r.detail,
                client_ip: r.client_ip,
                created_at: r.created_at,
            })
            .collect())
    }
}
