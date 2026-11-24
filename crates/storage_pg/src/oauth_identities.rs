//! PostgreSQL 版外部身份仓储实现。

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use rovortex_users::{ExternalIdentity, NewExternalIdentity, OauthIdentityRepository, UserError};

mod row {
    use chrono::{DateTime, Utc};
    use sqlx::FromRow;
    use uuid::Uuid;

    #[derive(FromRow)]
    pub struct IdentityRow {
        pub id: Uuid,
        pub user_id: Uuid,
        pub provider: String,
        pub provider_uid: String,
        pub email: Option<String>,
        pub raw_profile: Option<sqlx::types::Json<serde_json::Value>>,
        pub created_at: DateTime<Utc>,
    }
}

fn into_identity(r: row::IdentityRow) -> ExternalIdentity {
    ExternalIdentity {
        id: r.id,
        user_id: r.user_id,
        provider: r.provider,
        provider_uid: r.provider_uid,
        email: r.email,
        raw_profile: r.raw_profile.map(|j| j.0),
        created_at: r.created_at,
    }
}

pub struct PgOauthIdentityRepository {
    pool: PgPool,
}

impl PgOauthIdentityRepository {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl OauthIdentityRepository for PgOauthIdentityRepository {
    async fn find_by_external(
        &self,
        provider: &str,
        provider_uid: &str,
    ) -> Result<Option<ExternalIdentity>, UserError> {
        let row = sqlx::query_as!(
            row::IdentityRow,
            r#"SELECT id, user_id, provider, provider_uid, email, raw_profile AS "raw_profile: _", created_at FROM user_identities WHERE provider = $1 AND provider_uid = $2"#,
            provider,
            provider_uid,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| UserError::Hashing(e.to_string()))?;
        Ok(row.map(into_identity))
    }

    async fn create_for_user(
        &self,
        identity: NewExternalIdentity,
    ) -> Result<ExternalIdentity, UserError> {
        let row = sqlx::query_as!(
            row::IdentityRow,
            r#"INSERT INTO user_identities (id, user_id, provider, provider_uid, email, raw_profile)
               VALUES ($1, $2, $3, $4, $5, $6)
               RETURNING id, user_id, provider, provider_uid, email, raw_profile AS "raw_profile: _", created_at"#,
            Uuid::now_v7(),
            identity.user_id,
            identity.provider,
            identity.provider_uid,
            identity.email,
            identity.raw_profile,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| UserError::Hashing(e.to_string()))?;
        Ok(into_identity(row))
    }

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<ExternalIdentity>, UserError> {
        let rows = sqlx::query_as!(
            row::IdentityRow,
            r#"SELECT id, user_id, provider, provider_uid, email, raw_profile AS "raw_profile: _", created_at FROM user_identities WHERE user_id = $1 ORDER BY created_at"#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| UserError::Hashing(e.to_string()))?;
        Ok(rows.into_iter().map(into_identity).collect())
    }

    async fn remove(&self, user_id: Uuid, provider: &str) -> Result<(), UserError> {
        sqlx::query!(
            r#"DELETE FROM user_identities WHERE user_id = $1 AND provider = $2"#,
            user_id,
            provider,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UserError::Hashing(e.to_string()))?;
        Ok(())
    }

    async fn update_raw_profile(
        &self,
        user_id: Uuid,
        provider: &str,
        raw: Option<serde_json::Value>,
    ) -> Result<(), UserError> {
        sqlx::query!(
            r#"UPDATE user_identities SET raw_profile = $3
               WHERE user_id = $1 AND provider = $2"#,
            user_id,
            provider,
            raw,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| UserError::Hashing(e.to_string()))?;
        Ok(())
    }
}
