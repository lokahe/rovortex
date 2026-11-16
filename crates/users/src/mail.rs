//! 邮件发送抽象——业务层只声明「要发信」，不知道任何具体服务商。
//!
//! 实现方注意：发信是**尽力而为**的旁路操作（验证邮件丢了可重发），
//! 实现不应阻塞关键路径，失败记录日志即可。

use async_trait::async_trait;

#[async_trait]
pub trait MailSender: Send + Sync {
    /// 发送一封 HTML 邮件。返回 Err 表示投递前失败（网络/认证等）。
    async fn send(&self, to: &str, subject: &str, html: &str) -> Result<(), MailError>;
}

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("mail service error: {0}")]
    Service(String),
}
