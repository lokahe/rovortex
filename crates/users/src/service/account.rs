//! 账号生命周期：用户名/资料维护、会话管理、注销与恢复。

use uuid::Uuid;

use super::{token_utils::{generate_refresh_token, hash_refresh_token}, DELETED_STATUS};
use super::UserService;
use crate::audit::AuditAction;
use super::ProfilePatch;
use crate::domain::{User, UserError, validate_email, validate_username};
use crate::email_verification::{NewEmailVerification, VerificationPurpose};


impl UserService {
    /// 修改用户名：校验格式 → 唯一性（大小写不敏感，唯一索引兜底并发）→ 更新。
    /// 不吊销会话：用户名不参与 token 验证。
    pub async fn change_username(
        &self,
        user_id: Uuid,
        new_username: &str,
        client_ip: &str,
    ) -> Result<(), UserError> {
        validate_username(new_username)?;
        let user = self
            .repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::UserNotFound)?;
        if user.username.eq_ignore_ascii_case(new_username) {
            return Ok(()); // 没变（或仅大小写变化走唯一性更新）
        }
        if self.repo.find_by_username(new_username).await?.is_some() {
            return Err(UserError::UsernameTaken(new_username.into()));
        }
        self.repo.update_username(user_id, new_username).await?;
        self.audit(
            Some(user_id),
            AuditAction::UsernameChanged,
            format!("old={} new={new_username}", user.username),
            client_ip,
        ).await;
        Ok(())
    }

    /// 部分更新展示资料（PATCH 语义）。展示字段不参与 token 验证，不吊销会话。
    pub async fn update_profile(
        &self,
        user_id: Uuid,
        patch: ProfilePatch,
        client_ip: &str,
    ) -> Result<User, UserError> {
        validate_profile_patch(&patch)?;
        self.repo.find_by_id(user_id).await?.ok_or(UserError::UserNotFound)?;
        self.repo.update_profile(user_id, &patch).await?;
        self.audit(Some(user_id), AuditAction::ProfileUpdated, "profile", client_ip).await;
        self.repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::UserNotFound)
    }

    /// 请求注销账号：给登录邮箱发确认链接（一次性，15 分钟）。
    /// 防枚举不适用——调用方已登录，邮箱是自己的。
    pub async fn request_account_deletion(
        &self,
        user_id: Uuid,
        client_ip: &str,
    ) -> Result<(), UserError> {
        let user = self
            .repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::UserNotFound)?;
        self.audit(
            Some(user_id),
            AuditAction::AccountDeletionRequested,
            format!("email={}", user.email),
            client_ip,
        ).await;
        let raw = generate_refresh_token();
        self.email_verifications
            .insert(NewEmailVerification {
                id: Uuid::now_v7(),
                email: user.email.clone(),
                token_hash: hash_refresh_token(&raw),
                purpose: VerificationPurpose::AccountDeletion,
                user_id: Some(user_id),
                expires_at: chrono::Utc::now()
                    + chrono::Duration::minutes(self.config.email_verification_ttl_mins),
            })
            .await?;
        let link = format!(
            "{}/api/auth/account/confirm-deletion?token={}",
            self.verify_url_base, raw
        );
        let html = account_deletion_email_html(&user.username, &link, self.config.deletion_grace_days);
        if let Err(e) = self
            .mail
            .send(&user.email, "Rovortex 账号注销确认", &html)
            .await
        {
            tracing::warn!(email = %user.email, error = %e, "failed to send account deletion mail");
        }
        Ok(())
    }

    /// 确认注销：消费 token → 软删（status=2、清资料）→ 吊销全部会话。
    /// 原邮箱**保留占位**（唯一索引仍挡新注册），确保冷静期内可恢复、
    /// 且注销账号的邮箱不被冒用；冷静期后由 cron 硬删时自然释放。
    pub async fn confirm_account_deletion(
        &self,
        raw_token: &str,
        client_ip: &str,
    ) -> Result<(), UserError> {
        let token_hash = hash_refresh_token(raw_token);
        let (email, purpose, user_id) = self
            .email_verifications
            .consume_by_hash(&token_hash)
            .await?
            .ok_or(UserError::InvalidRefreshToken)?;
        if purpose != VerificationPurpose::AccountDeletion {
            return Err(UserError::InvalidRefreshToken);
        }
        let Some(user_id) = user_id else {
            return Err(UserError::InvalidRefreshToken);
        };
        self.repo.soft_delete(user_id).await?;
        self.refresh.revoke_all_for_user(user_id).await?;
        self.audit(Some(user_id), AuditAction::AccountDeleted, format!("email={email}"), client_ip).await;
        Ok(())
    }

    /// 请求恢复注销账号：向原邮箱发恢复链接。
    /// 原邮箱在注销后仍被占位（唯一索引保留），find_by_email 可命中软删行。
    /// 防枚举：未注册/未注销/冷静期外一律恒 Ok 不发信。
    pub async fn request_account_recovery(
        &self,
        email: &str,
        client_ip: &str,
    ) -> Result<(), UserError> {
        validate_email(email)?;
        let Some(user) = self.repo.find_by_email(email).await? else {
            return Ok(());
        };
        if user.status != DELETED_STATUS {
            return Ok(());
        }
        if let Some(deleted_at) = user.deleted_at {
            if chrono::Utc::now() - deleted_at > chrono::Duration::days(self.config.deletion_grace_days) {
                return Ok(());
            }
        }
        let user_id = user.id;
        self.audit(
            Some(user_id),
            AuditAction::AccountRecoveryRequested,
            format!("email={email}"),
            client_ip,
        ).await;
        let raw = generate_refresh_token();
        self.email_verifications
            .insert(NewEmailVerification {
                id: Uuid::now_v7(),
                email: email.to_string(),
                token_hash: hash_refresh_token(&raw),
                purpose: VerificationPurpose::AccountRecovery,
                user_id: Some(user_id),
                expires_at: chrono::Utc::now()
                    + chrono::Duration::minutes(self.config.email_verification_ttl_mins),
            })
            .await?;
        let link = format!(
            "{}/api/auth/account/confirm-recovery?token={}",
            self.verify_url_base, raw
        );
        let html = account_recovery_email_html(&user.username, &link, user.deleted_at, self.config.deletion_grace_days);
        if let Err(e) = self.mail.send(email, "Rovortex 账号恢复", &html).await {
            tracing::warn!(email, error = %e, "failed to send account recovery mail");
        }
        Ok(())
    }

    /// 确认恢复：消费 token → status 回 0、email 换回、清 deleted_at。
    /// 冷静期外（deleted_at 超过 config.deletion_grace_days）拒绝——数据可能已被 cron 清理。
    pub async fn confirm_account_recovery(
        &self,
        raw_token: &str,
        client_ip: &str,
    ) -> Result<(), UserError> {
        let token_hash = hash_refresh_token(raw_token);
        let (email, purpose, user_id) = self
            .email_verifications
            .consume_by_hash(&token_hash)
            .await?
            .ok_or(UserError::InvalidRefreshToken)?;
        if purpose != VerificationPurpose::AccountRecovery {
            return Err(UserError::InvalidRefreshToken);
        }
        let Some(user_id) = user_id else {
            return Err(UserError::InvalidRefreshToken);
        };
        let user = self
            .repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::UserNotFound)?;
        if user.status != DELETED_STATUS {
            return Err(UserError::InvalidRefreshToken);
        }
        if let Some(deleted_at) = user.deleted_at {
            if chrono::Utc::now() - deleted_at > chrono::Duration::days(self.config.deletion_grace_days) {
                return Err(UserError::InvalidRefreshToken);
            }
        }
        self.repo.restore(user_id).await?;
        self.audit(Some(user_id), AuditAction::AccountRestored, format!("email={email}"), client_ip).await;
        Ok(())
    }

    /// 踢掉指定会话（含当前会话自身：踢了就重新登录，语义最简）。
    pub async fn revoke_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        client_ip: &str,
    ) -> Result<(), UserError> {
        let revoked = self.refresh.revoke_by_id(user_id, session_id).await?;
        if !revoked {
            return Err(UserError::UserNotFound);
        }
        self.audit(
            Some(user_id),
            AuditAction::SessionRevoked,
            format!("session={session_id}"),
            client_ip,
        ).await;
        Ok(())
    }
}

/// 展示资料字段校验：长度上限 + URL 格式。仅拦明显非法值，
/// URL 渲染安全由前端负责（只存 URL 不存 HTML）。
fn validate_profile_patch(patch: &ProfilePatch) -> Result<(), UserError> {
    if let Some(Some(display_name)) = &patch.display_name {
        let len = display_name.chars().count();
        if !(1..=64).contains(&len) {
            return Err(UserError::InvalidUsername(
                "display_name length must be between 1 and 64".into(),
            ));
        }
    }
    if let Some(Some(bio)) = &patch.bio {
        let len = bio.chars().count();
        if !(1..=280).contains(&len) {
            return Err(UserError::InvalidUsername(
                "bio length must be between 1 and 280".into(),
            ));
        }
    }
    for url_field in [&patch.website_url, &patch.avatar_url] {
        if let Some(Some(url)) = url_field {
            let len = url.chars().count();
            if !(8..=256).contains(&len)
                || !(url.starts_with("http://") || url.starts_with("https://"))
            {
                return Err(UserError::InvalidUsername(
                    "url must start with http(s):// and be at most 256 chars".into(),
                ));
            }
        }
    }
    Ok(())
}

/// 注销确认邮件 HTML 模板。
fn account_deletion_email_html(username: &str, link: &str, grace_days: i64) -> String {
    format!(
        r#"<div style="font-family:sans-serif;max-width:480px;margin:0 auto">
  <h2>你好，{username}</h2>
  <p>你请求注销账号。请点击下面的链接确认（15 分钟内有效，仅可使用一次）：</p>
  <p><a href="{link}" style="display:inline-block;padding:10px 20px;background:#dc2626;color:#fff;text-decoration:none;border-radius:6px">确认注销</a></p>
  <p>注销后：</p>
  <ul style="color:#555;font-size:14px">
    <li>你将无法登录该账号，所有登录会话立即失效；</li>
    <li>绑定的第三方账号（GitHub 等）全部解除绑定；</li>
    <li>资料将被清空；</li>
    <li>邮箱与用户名仍保留占位，{grace_days} 天内可凭本邮箱恢复账号。</li>
  </ul>
  <p style="color:#888;font-size:13px">如果你没有请求注销，请忽略本邮件，账号不会被删除。</p>
</div>"#,
        grace_days = grace_days
    )
}

/// 账号恢复邮件 HTML 模板。
fn account_recovery_email_html(
    username: &str,
    link: &str,
    deleted_at: Option<chrono::DateTime<chrono::Utc>>,
    grace_days: i64,
) -> String {
    let deadline = deleted_at
        .map(|d| (d + chrono::Duration::days(grace_days)).format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "未知".into());
    format!(
        r#"<div style="font-family:sans-serif;max-width:480px;margin:0 auto">
  <h2>你好，{username}</h2>
  <p>你的账号处于注销冷静期。请点击下面的链接恢复（15 分钟内有效，仅可使用一次）：</p>
  <p><a href="{link}" style="display:inline-block;padding:10px 20px;background:#4f46e5;color:#fff;text-decoration:none;border-radius:6px">恢复账号</a></p>
  <p style="color:#888;font-size:13px">冷静期截止 {deadline}，逾期账号数据将被彻底删除，无法恢复。</p>
  <p style="color:#888;font-size:13px">如果你没有请求恢复，请忽略本邮件。</p>
</div>"#,
        deadline = deadline
    )
}
