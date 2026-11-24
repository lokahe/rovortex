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

    /// 按唯一 id 查找（鉴权后的资料读取等场景）。
    async fn find_by_id(&self, id: uuid::Uuid) -> Result<Option<User>, UserError>;

    /// 更新密码哈希（改密码）。调用方保证已完成旧密码校验。
    async fn update_password_hash(&self, id: uuid::Uuid, new_hash: &str) -> Result<(), UserError>;

    /// 标记邮箱已验证（注册验证信确认后）。
    async fn mark_email_verified(&self, id: uuid::Uuid) -> Result<(), UserError>;

    /// 更新邮箱（改邮箱确认后调用）。实现必须同时置 email_verified = true
    /// 并更新 updated_at；邮箱冲突由数据库唯一索引兜底。
    async fn update_email(&self, id: uuid::Uuid, new_email: &str) -> Result<(), UserError>;

    /// 更新用户名（改用户名）。实现必须更新 updated_at；
    /// 用户名冲突由数据库唯一索引兜底。
    async fn update_username(&self, id: uuid::Uuid, new_username: &str) -> Result<(), UserError>;

    /// 部分更新展示资料（PATCH 语义）：只更新 patch 中 Some 的字段，
    /// `Some(None)` 表示清空该字段。实现必须更新 updated_at。
    async fn update_profile(
        &self,
        id: uuid::Uuid,
        patch: &crate::service::ProfilePatch,
    ) -> Result<(), UserError>;

    /// 查询用户是否为管理员（admin API 每请求实时校验，撤销立即生效）。
    async fn is_admin(&self, id: uuid::Uuid) -> Result<bool, UserError>;

    /// 分页列出用户（admin 用户管理）。`q` 非空时按用户名/邮箱前缀匹配。
    async fn list_users(
        &self,
        q: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<User>, UserError>;

    /// 统计用户总数（与 list_users 相同的过滤条件，用于分页）。
    async fn count_users(&self, q: Option<&str>) -> Result<i64, UserError>;

    /// 设置用户状态（admin 封禁/解封）。实现方需同步更新 updated_at。
    async fn set_status(&self, id: uuid::Uuid, status: i16) -> Result<(), UserError>;

    /// 注销（软删）：置 status=2 + deleted_at、清空展示资料。
    /// 邮箱保留占位（唯一索引仍挡新注册），冷静期后由 cron 硬删释放。
    async fn soft_delete(&self, id: uuid::Uuid) -> Result<(), UserError>;

    /// 恢复注销账号（冷静期内）：status 回 0、清 deleted_at。
    async fn restore(&self, id: uuid::Uuid) -> Result<(), UserError>;

    /// 置为管理员（启动时 ROVORTEX_ADMIN_EMAILS 提升首个 admin）。
    async fn promote_admin(&self, id: uuid::Uuid) -> Result<(), UserError>;

    /// 统计各审计动作的发生次数（admin 仪表盘）。
    async fn count_audit_by_action(
        &self,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<(String, i64)>, UserError>;
}
