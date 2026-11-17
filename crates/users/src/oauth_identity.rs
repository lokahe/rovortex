//! 外部身份（OAuth / Magic Link）：平台侧身份与本地账号的映射。
//!
//! 业务层只见三元组 `(provider, provider_uid, email)`，协议细节住表现层。

use async_trait::async_trait;
use uuid::Uuid;

/// 一条外部身份绑定。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalIdentity {
    pub id: Uuid,
    pub user_id: Uuid,
    /// 'github' | 'google' | 'magic' ...
    pub provider: String,
    /// 平台侧唯一 id；magic 时为邮箱本身。
    pub provider_uid: String,
    /// 平台报告的邮箱（可能为空，X 就不给）。
    pub email: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// 新建外部身份绑定所需输入。
#[derive(Debug, Clone)]
pub struct NewExternalIdentity {
    pub user_id: Uuid,
    pub provider: String,
    pub provider_uid: String,
    pub email: Option<String>,
}

/// 外部身份持久化契约。
#[async_trait]
pub trait OauthIdentityRepository: Send + Sync {
    /// 按 (provider, provider_uid) 精确查找 —— 登录主键。
    async fn find_by_external(
        &self,
        provider: &str,
        provider_uid: &str,
    ) -> Result<Option<ExternalIdentity>, crate::domain::UserError>;

    /// 为已有用户挂一条新身份。UNIQUE(provider, provider_uid) 冲突由实现方报错。
    async fn create_for_user(
        &self,
        identity: NewExternalIdentity,
    ) -> Result<ExternalIdentity, crate::domain::UserError>;

    /// 列出某用户的全部外部身份。
    async fn list_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<ExternalIdentity>, crate::domain::UserError>;

    /// 解绑：删除用户的指定 provider 身份。
    async fn remove(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> Result<(), crate::domain::UserError>;
}
