//! 管理端业务：用户列表 / 详情聚合 / 封禁 / 仪表盘统计 / 首个 admin 提升。
//!
//! 与 UserService 平行：不持有会话签发与邮件逻辑，只编排
//! UserRepository / RefreshTokenRepository / AuditRepository / OauthIdentityRepository。
//! 授权（require_admin）仍在网关层；本模块假设调用方已通过鉴权。

use std::sync::Arc;

use uuid::Uuid;

use crate::audit::AuditRepository;
use crate::domain::{User, UserError};
use crate::oauth_identity::OauthIdentityRepository;
use crate::refresh_token::RefreshTokenRepository;
use crate::repository::UserRepository;

/// users.status 的封禁值（0001 建表 SMALLINT；0 = 活跃）。
pub const BANNED_STATUS: i16 = 1;
pub const ACTIVE_STATUS: i16 = 0;

/// 用户详情聚合：实体 + 绑定的外部身份 + 最近审计记录。
#[derive(Debug, Clone)]
pub struct UserDetail {
    pub user: User,
    pub identities: Vec<crate::oauth_identity::ExternalIdentity>,
    pub audit_logs: Vec<crate::audit::AuditEntry>,
}

/// 用户列表分页结果。
#[derive(Debug, Clone)]
pub struct UserPage {
    pub users: Vec<User>,
    pub total: i64,
}

/// 仪表盘统计。
#[derive(Debug, Clone)]
pub struct AdminStats {
    pub since: chrono::DateTime<chrono::Utc>,
    pub total_users: i64,
    pub events: Vec<(String, i64)>,
}

/// 管理业务服务。持有仓储抽象，具体实现在组合根注入。
#[derive(Clone)]
pub struct AdminService {
    repo: Arc<dyn UserRepository>,
    refresh: Arc<dyn RefreshTokenRepository>,
    audit: Arc<dyn AuditRepository>,
    identities: Arc<dyn OauthIdentityRepository>,
}

impl AdminService {
    pub fn new(
        repo: Arc<dyn UserRepository>,
        refresh: Arc<dyn RefreshTokenRepository>,
        audit: Arc<dyn AuditRepository>,
        identities: Arc<dyn OauthIdentityRepository>,
    ) -> Self {
        Self {
            repo,
            refresh,
            audit,
            identities,
        }
    }

    /// 启动时提升管理员：ROVORTEX_ADMIN_EMAILS 中的邮箱（大小写不敏感）
    /// 若已有账号则置 is_admin = true。仅组合根调用，无 HTTP 入口。
    pub async fn promote_admins(&self, emails: &[String]) -> Result<(), UserError> {
        for email in emails {
            let email = email.trim();
            if email.is_empty() {
                continue;
            }
            if let Some(user) = self.repo.find_by_email(email).await? {
                if !user.is_admin {
                    self.repo.promote_admin(user.id).await?;
                    tracing::info!(email = %user.email, user_id = %user.id, "promoted to admin");
                }
            } else {
                tracing::warn!(email, "admin email not found among users; will promote on next boot after the account exists");
            }
        }
        Ok(())
    }

    /// 分页用户列表（q 非空时按用户名/邮箱前缀匹配）。
    pub async fn list_users(
        &self,
        q: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<UserPage, UserError> {
        let users = self.repo.list_users(q, limit, offset).await?;
        let total = self.repo.count_users(q).await?;
        Ok(UserPage { users, total })
    }

    /// 单用户详情聚合（实体 + 身份绑定 + 最近 limit 条审计）。
    pub async fn user_detail(&self, user_id: Uuid, audit_limit: i64) -> Result<UserDetail, UserError> {
        let user = self
            .repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::UserNotFound)?;
        let identities = self.identities.list_for_user(user_id).await?;
        let audit_logs = self.audit.list_for_user(user_id, audit_limit).await?;
        Ok(UserDetail {
            user,
            identities,
            audit_logs,
        })
    }

    /// 封禁 / 解封。封禁同时吊销全部会话（已登录设备立即失效）——
    /// 两步是业务语义上的原子动作，不再散落在 HTTP 层。
    pub async fn set_ban(&self, user_id: Uuid, banned: bool) -> Result<(), UserError> {
        let status = if banned { BANNED_STATUS } else { ACTIVE_STATUS };
        self.repo.set_status(user_id, status).await?;
        if banned {
            let revoked = self.refresh.revoke_all_for_user(user_id).await?;
            tracing::info!(user_id = %user_id, revoked, "banned user sessions revoked");
        }
        Ok(())
    }

    /// 仪表盘统计：用户总数 + since 起各审计动作计数。
    pub async fn stats(&self, since: chrono::DateTime<chrono::Utc>) -> Result<AdminStats, UserError> {
        let total_users = self.repo.count_users(None).await?;
        let events = self.repo.count_audit_by_action(since).await?;
        Ok(AdminStats {
            since,
            total_users,
            events,
        })
    }
}
