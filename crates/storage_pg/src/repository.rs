//! PostgreSQL 版用户仓储实现。
//!
//! 通过 `sqlx` 以“原生 SQL + 编译期校验”方式落地 `UserRepository` 契约。

use async_trait::async_trait;

use sqlx::PgPool;

use rovortex_users::{NewUser, User, UserError, UserRepository};

/// PostgreSQL 仓储实现。
///
/// 依赖注入：`gateway_api::state::AppState::new()` 根据环境变量选择
/// `PgUserRepository` 或 `InMemoryUserRepository`。
pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    /// 通过 `ROVORTEX_DB`（或任一有效的 Postgres DSN）连接。
    pub async fn new(connection_string: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(connection_string).await?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn create(&self, new_user: NewUser) -> Result<User, UserError> {
        // TODO: 落地 SQL，包含：
        // - INSERT INTO users (...) VALUES (...) RETURNING ...
        // - 成功返回生成的 `User` 实体
        // - 冲突时返回 `UsernameTaken` / `EmailTaken`（靠唯一索引 + 错误码区分）
        Err(UserError::Hashing(
            "storage_pg: create() 尚未实现".into(),
        ))
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserError> {
        // TODO
        Err(UserError::Hashing(
            "storage_pg: find_by_username() 尚未实现".into(),
        ))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
        // TODO
        Err(UserError::Hashing(
            "storage_pg: find_by_email() 尚未实现".into(),
        ))
    }

    async fn find_by_login(&self, login: &str) -> Result<Option<User>, UserError> {
        // TODO
        Err(UserError::Hashing(
            "storage_pg: find_by_login() 尚未实现".into(),
        ))
    }
}
