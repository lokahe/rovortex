//! PostgreSQL 版用户仓储实现。
//!
//! 通过 `sqlx` 以“原生 SQL + 编译期校验”方式落地 `UserRepository` 契约。

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use rovortex_users::{NewUser, User, UserError, UserRepository};

/// 将 sqlx 错误映射为领域错误：唯一约束冲突对应 UsernameTaken / EmailTaken。
fn map_sqlx_err(e: sqlx::Error, kind: fn(String) -> UserError) -> UserError {
    if let sqlx::Error::Database(db_err) = &e {
        match db_err.constraint().unwrap_or_default() {
            "users_username_uniq" | "users_username_key" => {
                return UserError::UsernameTaken("unknown".into());
            }
            "users_email_uniq" | "users_email_key" => {
                return UserError::EmailTaken("unknown".into());
            }
            _ => {}
        }
    }
    kind(e.to_string())
}

mod row {
    use chrono::{DateTime, Utc};
    use sqlx::FromRow;
    use uuid::Uuid;

    /// 与 users 表列一一对应；`username_key`/`email_key`/`status`
    /// 由 DB 生成或预留，暂不在领域层使用。
    #[derive(FromRow)]
    #[allow(dead_code)]
    pub struct UserRow {
        pub id: Uuid,
        pub username: String,
        #[allow(dead_code)]
        pub username_key: String,
        pub email: String,
        #[allow(dead_code)]
        pub email_key: String,
        pub password_hash: Option<String>,
        #[allow(dead_code)]
        pub status: i16,
        pub email_verified: bool,
        pub is_admin: bool,
        pub created_at: DateTime<Utc>,
        pub updated_at: DateTime<Utc>,
    }
}

pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn into_user(r: row::UserRow) -> User {
    User {
        id: r.id,
        username: r.username,
        email: r.email,
        password_hash: r.password_hash,
        email_verified: r.email_verified,
        is_admin: r.is_admin,
        status: r.status,
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn create(&self, new_user: NewUser) -> Result<User, UserError> {
        let row = sqlx::query_as!(
            row::UserRow,
            r#"INSERT INTO users (id, username, email, password_hash)
               VALUES ($1, $2, $3, $4)
               RETURNING id, username, username_key, email, email_key, password_hash, status, email_verified, is_admin, created_at, updated_at"#,
            Uuid::now_v7(),
            new_user.username,
            new_user.email,
            new_user.password_hash,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;

        Ok(into_user(row))
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserError> {
        let row = sqlx::query_as!(
            row::UserRow,
            r#"SELECT id, username, username_key, email, email_key, password_hash, status, email_verified, is_admin, created_at, updated_at
               FROM users WHERE username_key = $1"#,
            username.to_lowercase(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;

        Ok(row.map(into_user))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
        let row = sqlx::query_as!(
            row::UserRow,
            r#"SELECT id, username, username_key, email, email_key, password_hash, status, email_verified, is_admin, created_at, updated_at
               FROM users WHERE email_key = $1"#,
            email.to_lowercase(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;

        Ok(row.map(into_user))
    }

    async fn find_by_login(&self, login: &str) -> Result<Option<User>, UserError> {
        let row = sqlx::query_as!(
            row::UserRow,
            r#"SELECT id, username, username_key, email, email_key, password_hash, status, email_verified, is_admin, created_at, updated_at
               FROM users WHERE username_key = $1 OR email_key = $1"#,
            login.to_lowercase(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;

        Ok(row.map(into_user))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, UserError> {
        let row = sqlx::query_as!(
            row::UserRow,
            r#"SELECT id, username, username_key, email, email_key, password_hash, status, email_verified, is_admin, created_at, updated_at
               FROM users WHERE id = $1"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;

        Ok(row.map(into_user))
    }

    async fn update_password_hash(&self, id: Uuid, new_hash: &str) -> Result<(), UserError> {
        sqlx::query!(
            r#"UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1"#,
            id,
            new_hash,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;
        Ok(())
    }

    async fn mark_email_verified(&self, id: Uuid) -> Result<(), UserError> {
        sqlx::query!(
            r#"UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1"#,
            id,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;
        Ok(())
    }

    async fn update_email(&self, id: Uuid, new_email: &str) -> Result<(), UserError> {
        sqlx::query!(
            r#"UPDATE users SET email = $2, email_verified = true, updated_at = now() WHERE id = $1"#,
            id,
            new_email,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;
        Ok(())
    }

    async fn update_username(&self, id: Uuid, new_username: &str) -> Result<(), UserError> {
        sqlx::query!(
            r#"UPDATE users SET username = $2, updated_at = now() WHERE id = $1"#,
            id,
            new_username,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;
        Ok(())
    }

    async fn is_admin(&self, id: Uuid) -> Result<bool, UserError> {
        let row =
            sqlx::query!(r#"SELECT is_admin AS "is_admin: bool" FROM users WHERE id = $1"#, id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;
        Ok(row.is_some_and(|r| r.is_admin))
    }

    async fn list_users(
        &self,
        q: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<User>, UserError> {
        let pattern = q.map(|s| format!("%{}%", s.to_lowercase()));
        let rows = sqlx::query_as!(
            row::UserRow,
            r#"SELECT id, username, username_key, email, email_key, password_hash, status, email_verified, is_admin, created_at, updated_at
               FROM users
               WHERE ($1::text IS NULL OR email_key LIKE $1 OR username_key LIKE $1)
               ORDER BY created_at DESC
               LIMIT $2 OFFSET $3"#,
            pattern,
            limit,
            offset,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;
        Ok(rows.into_iter().map(into_user).collect())
    }

    async fn count_users(&self, q: Option<&str>) -> Result<i64, UserError> {
        let pattern = q.map(|s| format!("%{}%", s.to_lowercase()));
        let row =
            sqlx::query!(
                r#"SELECT count(*) AS "count!: i64" FROM users
                   WHERE ($1::text IS NULL OR email_key LIKE $1 OR username_key LIKE $1)"#,
                pattern,
            )
            .fetch_one(&self.pool)
            .await
            .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;
        Ok(row.count)
    }

    async fn set_status(&self, id: Uuid, status: i16) -> Result<(), UserError> {
        let result = sqlx::query!(
            r#"UPDATE users SET status = $2, updated_at = now() WHERE id = $1"#,
            id,
            status,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;
        if result.rows_affected() == 0 {
            return Err(UserError::UserNotFound);
        }
        Ok(())
    }

    async fn promote_admin(&self, id: Uuid) -> Result<(), UserError> {
        let result = sqlx::query!(
            r#"UPDATE users SET is_admin = true, updated_at = now() WHERE id = $1"#,
            id,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;
        if result.rows_affected() == 0 {
            return Err(UserError::UserNotFound);
        }
        Ok(())
    }

    async fn count_audit_by_action(
        &self,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<(String, i64)>, UserError> {
        let rows = sqlx::query!(
            r#"SELECT action, count(*) AS "count!: i64"
               FROM audit_logs WHERE created_at >= $1
               GROUP BY action ORDER BY count(*) DESC"#,
            since,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;
        Ok(rows.into_iter().map(|r| (r.action, r.count)).collect())
    }
}
