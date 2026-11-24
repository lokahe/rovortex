//! 外部身份：OAuth/Magic 的身份登录入口、资料回填、绑定管理。

use uuid::Uuid;

use super::{ProfilePatch, Session, SessionContext, SessionView, UserService};
use crate::audit::AuditAction;
use crate::domain::{NewUser, UserError, validate_email, validate_username};
use crate::oauth_identity::{ExternalIdentity, ExternalProfile, NewExternalIdentity};
use crate::password::hash_password;


impl UserService {
    /// 外部身份登录（OAuth 回调 / Magic Link 确认后的共同入口）。
    ///
    /// 规则（按序）：
    /// 1. `(provider, provider_uid)` 已绑定 → 直接登录既有账号；
    /// 2. 未绑定但邮箱已被占用 → 挂到既有账号（账号合并，不建第二个账号）；
    /// 3. 全新 → 自动注册（username 自动生成去重，email_verified = true）。
    pub async fn login_with_identity(
        &self,
        provider: &str,
        provider_uid: &str,
        email: Option<&str>,
        profile: Option<&ExternalProfile>,
        client_ip: &str,
        ctx: &SessionContext,
    ) -> Result<Session, UserError> {
        // 1. 已绑定：直接登录（顺带刷新平台原始资料缓存）
        if let Some(identity) = self.identities.find_by_external(provider, provider_uid).await? {
            let user = self
                .repo
                .find_by_id(identity.user_id)
                .await?
                .ok_or(UserError::UserNotFound)?;
            if let Some(p) = profile
                && p.raw.is_some()
            {
                self.identities
                    .update_raw_profile(user.id, provider, p.raw.clone())
                    .await?;
            }
            self.backfill_profile(user.id, profile).await?;
            self.audit(
                Some(user.id),
                AuditAction::LoginSuccess,
                format!("provider={provider}"),
                client_ip,
            ).await;
            let user = self
                .repo
                .find_by_id(user.id)
                .await?
                .ok_or(UserError::UserNotFound)?;
            return self.issue_session(user, ctx).await;
        }

        // 2/3. 未绑定：需要 email 建账号或合并
        let email = email.ok_or_else(|| {
            UserError::Hashing(format!("provider {provider} reported no email; cannot bind"))
        })?;
        validate_email(email)?;

        let user = match self.repo.find_by_email(email).await? {
            // 2. 同邮箱既有账号：合并身份（同一 user 可绑多平台）
            Some(user) => {
                self.identities
                    .create_for_user(NewExternalIdentity {
                        user_id: user.id,
                        provider: provider.into(),
                        provider_uid: provider_uid.into(),
                        email: Some(email.into()),
                        raw_profile: profile.and_then(|p| p.raw.clone()),
                    })
                    .await?;
                self.backfill_profile(user.id, profile).await?;
                self.repo
                    .find_by_id(user.id)
                    .await?
                    .ok_or(UserError::UserNotFound)?
            }
            // 3. 全新用户：自动注册（平台已验证邮箱 → 直接标记 email_verified）
            None => {
                let username = self.unique_username_from(email, profile).await?;
                let mut user = self
                    .repo
                    .create(NewUser {
                        username,
                        email: email.into(),
                        password_hash: None,
                    })
                    .await?;
                self.repo.mark_email_verified(user.id).await?;
                user.email_verified = true;
                self.identities
                    .create_for_user(NewExternalIdentity {
                        user_id: user.id,
                        provider: provider.into(),
                        provider_uid: provider_uid.into(),
                        email: Some(email.into()),
                        raw_profile: profile.and_then(|p| p.raw.clone()),
                    })
                    .await?;
                // 新用户直接写入资料（首体验最重要）
                self.backfill_profile(user.id, profile).await?;
                self.audit(
                    Some(user.id),
                    AuditAction::Register,
                    format!("username={}", user.username),
                    client_ip,
                ).await;
                self.repo
                    .find_by_id(user.id)
                    .await?
                    .ok_or(UserError::UserNotFound)?
            }
        };

        self.audit(
            Some(user.id),
            AuditAction::LoginSuccess,
            format!("provider={provider}"),
            client_ip,
        ).await;
        self.issue_session(user, ctx).await
    }

    /// 回填规范资料：users 表该字段为空才写入平台值，非空不覆盖
    ///（非空即视为用户编辑过）。无 profile 或全空则不动。
    async fn backfill_profile(
        &self,
        user_id: Uuid,
        profile: Option<&ExternalProfile>,
    ) -> Result<(), UserError> {
        let Some(p) = profile else {
            return Ok(());
        };
        let user = match self.repo.find_by_id(user_id).await? {
            Some(u) => u,
            None => return Ok(()),
        };
        // 空缺才回填：users 字段为 None 时写入平台值；非空即视为用户编辑过，不动
        let patch = ProfilePatch {
            display_name: if user.display_name.is_none() { Some(p.display_name.clone()) } else { None },
            avatar_url: if user.avatar_url.is_none() { Some(p.avatar_url.clone()) } else { None },
            bio: if user.bio.is_none() { Some(p.bio.clone()) } else { None },
            website_url: if user.website_url.is_none() { Some(p.website_url.clone()) } else { None },
        };
        if patch.display_name.is_some()
            || patch.avatar_url.is_some()
            || patch.bio.is_some()
            || patch.website_url.is_some()
        {
            self.repo.update_profile(user_id, &patch).await?;
        }
        Ok(())
    }

    /// 从邮箱前缀推导用户名，冲突时追加数字后缀（如 alice → alice2 → alice3）。
    /// 有平台资料时优先用 display_name / 平台用户名风格字段做候选（需通过校验）。
    pub(super) async fn unique_username_from(
        &self,
        email: &str,
        profile: Option<&ExternalProfile>,
    ) -> Result<String, UserError> {
        // 平台提供的展示名若合法且未被占用，优先采用（如 github login）
        if let Some(p) = profile {
            for candidate_src in [p.display_name.as_deref()] {
                let Some(src) = candidate_src else { continue };
                let candidate: String = src
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if candidate.len() < 3 {
                    continue;
                }
                if self.repo.find_by_username(&candidate).await?.is_none()
                    && validate_username(&candidate).is_ok()
                {
                    return Ok(candidate);
                }
            }
        }
        let base: String = email
            .split('@')
            .next()
            .unwrap_or("user")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let base = if base.len() >= 3 {
            base
        } else {
            format!("user{base}")
        };
        let mut candidate = base.clone();
        let mut n = 1u32;
        while self.repo.find_by_username(&candidate).await?.is_some() {
            n += 1;
            candidate = format!("{base}{n}");
        }
        validate_username(&candidate)?;
        Ok(candidate)
    }

    /// 为无密码账号设置初值密码（不需要验旧密码）；已有密码的账号必须走 change_password。
    pub async fn set_password(
        &self,
        user_id: Uuid,
        new_password: &str,
        client_ip: &str,
    ) -> Result<(), UserError> {
        self.validate_password_len(new_password)?;
        let user = self
            .repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::UserNotFound)?;
        if user.password_hash.is_some() {
            return Err(UserError::InvalidCredentials);
        }
        // 无密码账号必须至少绑定一种外部身份，否则账号将完全无法登录
        if self.identities.list_for_user(user_id).await?.is_empty() {
            return Err(UserError::UserNotFound);
        }
        let new_hash = hash_password(new_password)?;
        self.repo.update_password_hash(user_id, &new_hash).await?;
        self.audit(Some(user_id), AuditAction::PasswordChanged, "set_password", client_ip).await;
        Ok(())
    }

    /// 列出某用户的全部外部身份（设置页「已绑定平台」）。
    pub async fn list_identities(&self, user_id: Uuid) -> Result<Vec<ExternalIdentity>, UserError> {
        self.identities.list_for_user(user_id).await
    }

    /// 解绑外部身份。守门：解绑后必须仍剩至少一种登录方式
    /// （密码已设或还有其他身份），否则拒绝——防解绑成无法登录的死号。
    pub async fn unbind_identity(&self, user_id: Uuid, provider: &str, client_ip: &str) -> Result<(), UserError> {
        self.repo.find_by_id(user_id).await?.ok_or(UserError::UserNotFound)?;
        let bound = self.identities.list_for_user(user_id).await?;
        if !bound.iter().any(|i| i.provider == provider) {
            return Err(UserError::UserNotFound);
        }
        let has_password = self
            .repo
            .find_by_id(user_id)
            .await?
            .is_some_and(|u| u.password_hash.is_some());
        let other_identities = bound.iter().any(|i| i.provider != provider);
        if !has_password && !other_identities {
            return Err(UserError::LastLoginMethod);
        }
        self.identities.remove(user_id, provider).await?;
        self.audit(
            Some(user_id),
            AuditAction::IdentityUnlinked,
            format!("provider={provider}"),
            client_ip,
        ).await;
        Ok(())
    }

    /// 列出当前用户的全部有效会话（设备列表）。
    pub async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<SessionView>, UserError> {
        self.refresh.list_active_for_user(user_id).await
    }
}
