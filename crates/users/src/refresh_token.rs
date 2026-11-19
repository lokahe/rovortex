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
    /// 设备标签（客户端自报或 UA 解析结果），仅用于"人认设备"。
    pub device_label: Option<String>,
    /// UA 解析结果（如 "Chrome 130 · Windows"），不存原始 UA 串。
    pub ua: Option<String>,
    /// 粗粒度 IP（前两段），完整 IP 不落库。
    pub ip: Option<String>,
}

/// 会话列表条目（/me/sessions）。
#[derive(Debug, Clone)]
pub struct SessionView {
    pub id: Uuid,
    pub device_label: Option<String>,
    pub ua: Option<String>,
    pub ip: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
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

    /// 某用户的全部有效会话（未吊销且未过期），按创建时间倒序。
    async fn list_active_for_user(&self, user_id: Uuid) -> Result<Vec<SessionView>, UserError>;

    /// 吊销指定会话（校验归属）。返回是否确有此有效会话。
    async fn revoke_by_id(&self, user_id: Uuid, id: Uuid) -> Result<bool, UserError>;
}
