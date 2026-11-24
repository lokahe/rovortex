//! 邮箱相关用例：注册后补验证 / 改邮箱 / Magic Link 登录。

use uuid::Uuid;

use super::{Session, SessionContext, UserService, token_utils::{generate_refresh_token, hash_refresh_token}};
use crate::audit::AuditAction;
use crate::domain::{UserError, validate_email};
use crate::email_verification::{NewEmailVerification, VerificationPurpose};


impl UserService {
    /// 请求注册邮箱验证：给指定邮箱发确认信。
    ///
    /// 防枚举：无论邮箱是否已注册，都返回 Ok（不泄露注册状态）。
    /// 发信失败不阻断流程（用户可重发），只记录。
    pub async fn request_email_verification(&self, email: &str, client_ip: &str) -> Result<(), UserError> {
        validate_email(email)?;
        if let Some(user) = self.repo.find_by_email(email).await? {
            if user.email_verified {
                return Ok(()); // 已验证，不发信
            }
            self.audit(
                Some(user.id),
                AuditAction::EmailVerificationRequested,
                format!("email={email}"),
                client_ip,
            ).await;
            let raw = generate_refresh_token();
            self.email_verifications
                .insert(NewEmailVerification {
                    id: Uuid::now_v7(),
                    email: email.to_string(),
                    token_hash: hash_refresh_token(&raw),
                    purpose: VerificationPurpose::Signup,
                    user_id: None,
                    expires_at: chrono::Utc::now()
                        + chrono::Duration::minutes(self.config.email_verification_ttl_mins),
                })
                .await?;
            let link = format!(
                "{}/api/auth/verify-email/confirm?token={}",
                self.verify_url_base, raw
            );
            let html = verification_email_html(&user.username, &link);
            if let Err(e) = self.mail.send(email, "Rovortex 邮箱验证", &html).await {
                tracing::warn!(email, error = %e, "failed to send verification email");
            }
        }
        Ok(())
    }

    /// 确认注册验证：校验 token → 标记邮箱已验证。
    pub async fn confirm_email_verification(&self, raw_token: &str, client_ip: &str) -> Result<(), UserError> {
        let token_hash = hash_refresh_token(raw_token);
        let (email, purpose, user_id) = self
            .email_verifications
            .consume_by_hash(&token_hash)
            .await?
            .ok_or(UserError::InvalidRefreshToken)?;
        if purpose != VerificationPurpose::Signup {
            return Err(UserError::InvalidRefreshToken);
        }
        let user = self
            .repo
            .find_by_email(&email)
            .await?
            .ok_or(UserError::UserNotFound)?;
        // user_id 在 signup 流程为 None，以邮箱反查为准。
        let _ = user_id;
        self.audit(Some(user.id), AuditAction::EmailVerified, format!("email={email}"), client_ip).await;
        self.repo.mark_email_verified(user.id).await
    }

    /// 请求改邮箱：给新邮箱发确认信（确认后才真正改）。
    pub async fn request_email_change(
        &self,
        user_id: Uuid,
        new_email: &str,
        client_ip: &str,
    ) -> Result<(), UserError> {
        validate_email(new_email)?;
        let user = self
            .repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::UserNotFound)?;
        if user.email.eq_ignore_ascii_case(new_email) {
            return Ok(()); // 没变，免发信
        }
        // 唯一性预检查（并发撞车仍由唯一索引兜底）
        if self.repo.find_by_email(new_email).await?.is_some() {
            return Err(UserError::EmailTaken(new_email.into()));
        }

        self.audit(
            Some(user_id),
            AuditAction::EmailChangeRequested,
            format!("old={} new={new_email}", user.email),
            client_ip,
        ).await;

        let raw = generate_refresh_token();
        self.email_verifications
            .insert(NewEmailVerification {
                id: Uuid::now_v7(),
                email: new_email.to_string(),
                token_hash: hash_refresh_token(&raw),
                purpose: VerificationPurpose::EmailChange,
                user_id: Some(user_id),
                expires_at: chrono::Utc::now()
                    + chrono::Duration::minutes(self.config.email_verification_ttl_mins),
            })
            .await?;
        let link = format!(
            "{}/api/auth/verify-email/confirm?token={}",
            self.verify_url_base, raw
        );
        let html = email_change_email_html(&user.username, new_email, &link);
        if let Err(e) = self.mail.send(new_email, "Rovortex 邮箱变更确认", &html).await {
            tracing::warn!(new_email, error = %e, "failed to send email change mail");
        }
        Ok(())
    }

    /// 确认改邮箱：校验 token → 更新邮箱（同时置 email_verified）。
    pub async fn confirm_email_change(&self, raw_token: &str, client_ip: &str) -> Result<(), UserError> {
        let token_hash = hash_refresh_token(raw_token);
        let (email, purpose, user_id) = self
            .email_verifications
            .consume_by_hash(&token_hash)
            .await?
            .ok_or(UserError::InvalidRefreshToken)?;
        let Some(user_id) = user_id else {
            return Err(UserError::InvalidRefreshToken);
        };
        if purpose != VerificationPurpose::EmailChange {
            return Err(UserError::InvalidRefreshToken);
        }
        self.audit(Some(user_id), AuditAction::EmailChanged, format!("new={email}"), client_ip).await;
        self.repo.update_email(user_id, &email).await
    }

    /// 请求 Magic Link 登录：给邮箱发一次性登录链接（15 分钟有效）。
    ///
    /// 防枚举：无论邮箱是否已注册都发信（未注册 = 登录即注册），
    /// 但对已注册邮箱记审计；恒返回 Ok。
    /// 发信频率限制由表现层实施（同邮箱 1 分钟 1 条）。
    pub async fn request_magic_link(&self, email: &str, client_ip: &str) -> Result<(), UserError> {
        validate_email(email)?;
        if let Some(user) = self.repo.find_by_email(email).await? {
            self.audit(
                Some(user.id),
                AuditAction::MagicLinkRequested,
                format!("email={email}"),
                client_ip,
            ).await;
        }

        let raw = generate_refresh_token();
        self.email_verifications
            .insert(NewEmailVerification {
                id: Uuid::now_v7(),
                email: email.to_string(),
                token_hash: hash_refresh_token(&raw),
                purpose: VerificationPurpose::MagicLink,
                user_id: None,
                expires_at: chrono::Utc::now()
                    + chrono::Duration::minutes(self.config.email_verification_ttl_mins),
            })
            .await?;
        let link = format!(
            "{}/api/auth/magic-link/verify?token={}",
            self.verify_url_base, raw
        );
        let html = magic_link_email_html(email, &link);
        if let Err(e) = self.mail.send(email, "Rovortex 登录链接", &html).await {
            tracing::warn!(email, error = %e, "failed to send magic link mail");
        }
        Ok(())
    }

    /// 验证 Magic Link：消费一次性 token → 以 ("magic", email) 身份登录
    /// （已注册直接登录；未注册自动建号）。返回完整会话。
    pub async fn verify_magic_link(
        &self,
        raw_token: &str,
        client_ip: &str,
        ctx: &SessionContext,
    ) -> Result<Session, UserError> {
        let token_hash = hash_refresh_token(raw_token);
        let (email, purpose, _) = self
            .email_verifications
            .consume_by_hash(&token_hash)
            .await?
            .ok_or(UserError::InvalidRefreshToken)?;
        if purpose != VerificationPurpose::MagicLink {
            return Err(UserError::InvalidRefreshToken);
        }
        // 收件权即身份：能读到邮件 = 邮箱主人 = 平台已验证邮箱
        self.login_with_identity("magic", &email, Some(&email), None, client_ip, ctx)
            .await
    }
}

/// 验证邮件 HTML 模板（注册）。
fn verification_email_html(username: &str, link: &str) -> String {
    format!(
        r#"<div style="font-family:sans-serif;max-width:480px;margin:0 auto">
  <h2>你好，{username}</h2>
  <p>请点击下面的链接完成邮箱验证（15 分钟内有效）：</p>
  <p><a href="{link}" style="display:inline-block;padding:10px 20px;background:#4f46e5;color:#fff;text-decoration:none;border-radius:6px">验证邮箱</a></p>
  <p style="color:#888;font-size:13px">如果按钮无法点击，请复制此链接到浏览器：<br><a href="{link}">{link}</a></p>
  <p style="color:#888;font-size:13px">如果你没有注册过 Rovortex，请忽略本邮件。</p>
</div>"#
    )
}

/// 验证邮件 HTML 模板（改邮箱确认）。
fn email_change_email_html(username: &str, new_email: &str, link: &str) -> String {
    format!(
        r#"<div style="font-family:sans-serif;max-width:480px;margin:0 auto">
  <h2>你好，{username}</h2>
  <p>你请求将账号邮箱变更为 <strong>{new_email}</strong>。请点击下面的链接确认（15 分钟内有效）：</p>
  <p><a href="{link}" style="display:inline-block;padding:10px 20px;background:#4f46e5;color:#fff;text-decoration:none;border-radius:6px">确认变更</a></p>
  <p style="color:#888;font-size:13px">如果你没有发起过此操作，请忽略本邮件，账号邮箱不会变更。</p>
</div>"#
    )
}

/// Magic Link 登录邮件 HTML 模板。
fn magic_link_email_html(email: &str, link: &str) -> String {
    format!(
        r#"<div style="font-family:sans-serif;max-width:480px;margin:0 auto">
  <h2>登录 Rovortex</h2>
  <p>你好 {email}，请点击下面的链接登录（15 分钟内有效，仅可使用一次）：</p>
  <p><a href="{link}" style="display:inline-block;padding:10px 20px;background:#4f46e5;color:#fff;text-decoration:none;border-radius:6px">一键登录</a></p>
  <p style="color:#888;font-size:13px">如果按钮无法点击，请复制此链接到浏览器：<br><a href="{link}">{link}</a></p>
  <p style="color:#888;font-size:13px">如果你没有请求登录，请忽略本邮件，任何人没有此链接都无法登录你的账号。</p>
</div>"#
    )
}
