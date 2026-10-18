//! 用户仓储抽象 —— 数据库选型落地前先定义契约（Dependency Inversion）。
//!
//! 现有 / 计划中的实现：
//! - [`crate::in_memory`]：内存实现（当前，用于开发与集成测试）
//! - `crates/storage_pg`（规划中）：PostgreSQL + sqlx 实现
//!
//! 新增持久化实现时只需实现本 trait，并在组合根（`gateway_api::state`）切换注入，
//! 业务层代码零改动。

use async_trait::async_trait;

use crate::domain::{NewUser, User, UserError};

/// 用户持久化契约。
///
/// 实现方必须保证：
/// 1. `username` 与 `email` 的唯一性（冲突时返回 `UsernameTaken` / `EmailTaken`）；
/// 2. 大小写不敏感的唯一性（`Alice` 与 `alice` 视为同名）；
/// 3. 线程安全（`Send + Sync`），允许跨 tokio 任务共享。
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// 插入新用户，成功返回已持久化的实体（含生成的 id 与时间戳）。
    async fn create(&self, new_user: NewUser) -> Result<User, UserError>;

    /// 按用户名精确查找。
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserError>;

    /// 按邮箱精确查找。
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserError>;

    /// 按登录名（用户名 **或** 邮箱）查找，登录场景专用。
    async fn find_by_login(&self, login: &str) -> Result<Option<User>, UserError>;
}
