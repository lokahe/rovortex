//! Refresh token 仓储抽象。
//!
//! 安全约定：**领域层只接受/返回 token 的 SHA-256 哈希**，明文 token
//! 只在签发瞬间存在于内存，仓储与数据库永远不接触明文。

use async_trait::async_trait;
use uuid::Uuid;

use crate::domain::UserError;

#[derive(Debug, Clone)]
pub struct NewRefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

#[async_trait]
pub trait RefreshTokenRepository: Send + Sync {
    /// 存入新 token（哈希）。
    async fn insert(&self, token: NewRefreshToken) -> Result<(), UserError>;

    /// 按哈希查找有效 token：存在且未吊销未过期则返回 (user_id, token_hash)。
    async fn find_active_by_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<(Uuid, String)>, UserError>;

    /// 吊销单个 token（登出）。
    async fn revoke_by_hash(&self, token_hash: &str) -> Result<(), UserError>;

    /// 吊销某用户全部有效 token（改密码 / 封禁）。
    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<u64, UserError>;
}
