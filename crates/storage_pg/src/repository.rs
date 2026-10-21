//! PostgreSQL 版用户仓储实现。
//!
//! 通过 `sqlx` 以“原生 SQL + 编译期校验”方式落地 `UserRepository` 契约。

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use rovortex_users::{NewUser, User, UserError, UserRepository};

mod row {
    use chrono::{DateTime, Utc};
    use sqlx::FromRow;
    use uuid::Uuid;

    #[derive(FromRow)]
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
    pub async fn new(connection_string: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(connection_string).await?;
        Ok(Self { pool })
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
        .await?;

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
        .await?;

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
        .await?;

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
        .await?;

        Ok(row.map(|r| User {
            id: r.id,
            username: r.username,
            email: r.email,
            password_hash: r.password_hash,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }))
    }
}
