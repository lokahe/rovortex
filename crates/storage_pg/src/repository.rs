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
        pub username_key: String,
        pub email: String,
        pub email_key: String,
        pub password_hash: String,
        pub status: i16,
        pub created_at: DateTime<Utc>,
        pub updated_at: DateTime<Utc>,
    }
}

pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    /// 由调用方（组合根）提供连接池：迁移与业务查询共用同一个池。
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn create(&self, new_user: NewUser) -> Result<User, UserError> {
        let row = sqlx::query_as!(
            row::UserRow,
            r#"INSERT INTO users (id, username, email, password_hash)
               VALUES ($1, $2, $3, $4)
               RETURNING id, username, username_key, email, email_key, password_hash, status, created_at, updated_at"#,
            Uuid::now_v7(),
            new_user.username,
            new_user.email,
            new_user.password_hash,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;

        Ok(User {
            id: row.id,
            username: row.username,
            email: row.email,
            password_hash: row.password_hash,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserError> {
        let row = sqlx::query_as!(
            row::UserRow,
            r#"SELECT id, username, username_key, email, email_key, password_hash, status, created_at, updated_at
               FROM users WHERE username_key = $1"#,
            username.to_lowercase(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;

        Ok(row.map(|r| User {
            id: r.id,
            username: r.username,
            email: r.email,
            password_hash: r.password_hash,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
        let row = sqlx::query_as!(
            row::UserRow,
            r#"SELECT id, username, username_key, email, email_key, password_hash, status, created_at, updated_at
               FROM users WHERE email_key = $1"#,
            email.to_lowercase(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;

        Ok(row.map(|r| User {
            id: r.id,
            username: r.username,
            email: r.email,
            password_hash: r.password_hash,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    async fn find_by_login(&self, login: &str) -> Result<Option<User>, UserError> {
        let row = sqlx::query_as!(
            row::UserRow,
            r#"SELECT id, username, username_key, email, email_key, password_hash, status, created_at, updated_at
               FROM users WHERE username_key = $1 OR email_key = $1"#,
            login.to_lowercase(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;

        Ok(row.map(|r| User {
            id: r.id,
            username: r.username,
            email: r.email,
            password_hash: r.password_hash,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, UserError> {
        let row = sqlx::query_as!(
            row::UserRow,
            r#"SELECT id, username, username_key, email, email_key, password_hash, status, created_at, updated_at
               FROM users WHERE id = $1"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| map_sqlx_err(e, UserError::Hashing))?;

        Ok(row.map(|r| User {
            id: r.id,
            username: r.username,
            email: r.email,
            password_hash: r.password_hash,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
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
}
