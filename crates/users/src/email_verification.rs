//! 邮箱验证仓储抽象。
//!
//! 安全约定同 refresh_tokens：token 只以 SHA-256 哈希落库。

use async_trait::async_trait;
use uuid::Uuid;

use crate::domain::UserError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationPurpose {
    /// 注册后验证邮箱归属。
    Signup,
    /// 改邮箱：向新邮箱发确认信（token 关联 user_id）。
    EmailChange,
    /// 免密登录：token 即登录凭据（验证后签发会话）。
    MagicLink,
    /// 忘记密码：token 授权重置该邮箱账号的密码。
    PasswordReset,
    /// 账号注销：确认邮件链接后执行软删。
    AccountDeletion,
    /// 注销恢复（冷静期内）：token 授权恢复账号并取回原邮箱。
    AccountRecovery,
    /// 统一入口：邮箱+密码一框登录/注册，码即登录凭据（已注册收码静默设密，未注册建号）。
    EmailEntry,
}

impl VerificationPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerificationPurpose::Signup => "signup",
            VerificationPurpose::EmailChange => "email_change",
            VerificationPurpose::MagicLink => "magic_link",
            VerificationPurpose::PasswordReset => "password_reset",
            VerificationPurpose::AccountDeletion => "account_deletion",
            VerificationPurpose::AccountRecovery => "account_recovery",
            VerificationPurpose::EmailEntry => "email_entry",
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewEmailVerification {
    pub id: Uuid,
    pub email: String,
    pub token_hash: String,
    pub purpose: VerificationPurpose,
    /// EmailChange 时必须提供（确认后改这个用户的邮箱）；Signup 为 None。
    pub user_id: Option<Uuid>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait EmailVerificationRepository: Send + Sync {
    async fn insert(&self, verification: NewEmailVerification) -> Result<(), UserError>;

    /// 按哈希查找有效验证（未消费未过期），命中即消费（一次性）。
    /// 返回 (email, purpose, user_id)。
    async fn consume_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<(String, VerificationPurpose, Option<Uuid>)>, UserError>;
}
