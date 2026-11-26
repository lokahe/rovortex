//! `rovortex_users::SettingsStore` 的 PostgreSQL 实现（app_settings 表）。

use std::collections::HashMap;

use sqlx::PgPool;

use rovortex_users::settings::{SettingsError, SettingsStore};

pub struct PgSettingsStore {
    pool: PgPool,
}

impl PgSettingsStore {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl SettingsStore for PgSettingsStore {
    async fn load_all(&self) -> Result<HashMap<String, String>, SettingsError> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT key, value FROM app_settings")
                .fetch_all(&self.pool)
                .await
                .map_err(|e| SettingsError(e.to_string()))?;
        Ok(rows.into_iter().collect())
    }

    async fn put(&self, key: &str, value: &str) -> Result<(), SettingsError> {
        sqlx::query!(
            r#"INSERT INTO app_settings (key, value, updated_at)
               VALUES ($1, $2, now())
               ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()"#,
            key,
            value,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| SettingsError(e.to_string()))?;
        Ok(())
    }
}
