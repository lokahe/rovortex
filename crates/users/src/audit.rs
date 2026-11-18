//! 审计日志仓储抽象。
//!
//! 只追加。失败也记（login_failure），构成安全事件证据链。

use async_trait::async_trait;
use uuid::Uuid;

/// 审计动作枚举：写库前归一成稳定字符串，避免各处手滑拼错。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    Register,
    LoginSuccess,
    LoginFailure,
    Logout,
    RefreshSuccess,
    RefreshFailure,
    PasswordChanged,
    EmailVerificationRequested,
    EmailVerified,
    EmailChangeRequested,
    EmailChanged,
    MagicLinkRequested,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditAction::Register => "register",
            AuditAction::LoginSuccess => "login_success",
            AuditAction::LoginFailure => "login_failure",
            AuditAction::Logout => "logout",
            AuditAction::RefreshSuccess => "refresh_success",
            AuditAction::RefreshFailure => "refresh_failure",
            AuditAction::PasswordChanged => "password_changed",
            AuditAction::EmailVerificationRequested => "email_verification_requested",
            AuditAction::EmailVerified => "email_verified",
            AuditAction::EmailChangeRequested => "email_change_requested",
            AuditAction::EmailChanged => "email_changed",
            AuditAction::MagicLinkRequested => "magic_link_requested",
        }
    }
}

/// 一条审计记录。user_id 可空（如未注册邮箱的 login_failure）。
#[derive(Debug, Clone)]
pub struct NewAuditLog {
    pub user_id: Option<Uuid>,
    pub action: AuditAction,
    /// 补充上下文（如目标邮箱、失败原因类别）。不含密码/token 等敏感值。
    pub detail: String,
    pub client_ip: String,
}

#[async_trait]
pub trait AuditRepository: Send + Sync {
    /// 写入失败不应影响主流程：实现方需吞掉并只记日志。
    async fn append(&self, entry: NewAuditLog) -> Result<(), crate::domain::UserError>;
}
