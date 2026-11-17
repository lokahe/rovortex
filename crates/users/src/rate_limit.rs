//! 登录限流抽象。
//!
//! 契约：同一 (ip, login) 组合连续失败达到阈值后，在窗口期内拒绝尝试。
//! 成功登录重置计数；拒绝期间不消耗密码哈希算力（防 DoS/暴力破解双目的）。

use crate::domain::UserError;

#[async_trait::async_trait]
pub trait LoginGuard: Send + Sync {
    /// 尝试前检查：锁定中返回 Err(TooManyAttempts)。
    async fn check(&self, key: &str) -> Result<(), UserError>;

    /// 记录一次失败。
    async fn record_failure(&self, key: &str);

    /// 登录成功后清除计数。
    async fn record_success(&self, key: &str);
}

/// 组合限流键：客户端 IP + 登录标识（小写归一）。
pub fn guard_key(ip: &str, login: &str) -> String {
    format!("{ip}:{login}")
}
