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
}

impl VerificationPurpose {
    pub fn as_str(&self) -> &'static str {
        match self {
            VerificationPurpose::Signup => "signup",
            VerificationPurpose::EmailChange => "email_change",
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
