//! 找回密码：verified 门 + 码/链接双凭据。

use super::{UserService, token_utils::{generate_refresh_token, hash_refresh_token}};
use crate::audit::AuditAction;
use crate::domain::{UserError, validate_email};
use crate::email_verification::{NewEmailVerification, VerificationPurpose};
use crate::password::hash_password;
use uuid::Uuid;

impl UserService {
    /// 忘记密码：给邮箱发重置凭据（6 位码 + 链接双通道，一次性，15 分钟有效）。
    ///
    /// 防枚举：未注册 / 无密码 / 邮箱未验证的账号不发信但恒返回 Ok（不泄露注册状态）。
    /// 只对有密码的账号发信——纯 OAuth/Magic 用户无需密码重置。
    /// verified 门：未验证邮箱的账号不参与密码重置——否则填错邮箱即可重置接管。
    /// 发信失败不阻断流程（用户可重发），只记录。
    pub async fn request_password_reset(&self, email: &str, client_ip: &str) -> Result<(), UserError> {
        validate_email(email)?;
        let Some(user) = self.repo.find_by_email(email).await? else {
            return Ok(());
        };
        if user.password_hash.is_none() || !user.email_verified {
            return Ok(());
        }
        self.audit(
            Some(user.id),
            AuditAction::PasswordResetRequested,
            format!("email={email}"),
            client_ip,
        ).await;
        let code = Self::generate_signup_code();
        let raw = generate_refresh_token();
        for token in [&code, &raw] {
            self.email_verifications
                .insert(NewEmailVerification {
                    id: Uuid::now_v7(),
                    email: email.to_string(),
                    token_hash: hash_refresh_token(token),
                    purpose: VerificationPurpose::PasswordReset,
                    user_id: Some(user.id),
                    expires_at: chrono::Utc::now()
                        + chrono::Duration::minutes(self.config.email_verification_ttl_mins),
                })
                .await?;
        }
        let link = format!(
            "{}/api/auth/password-reset/confirm?token={}",
            self.verify_url_base, raw
        );
        let html = self.password_reset_email_html(&user.username, &code, &link);
        if let Err(e) = self.mail.send(email, "Rovortex 密码重置", &html).await {
            tracing::warn!(email, error = %e, "failed to send password reset mail");
        }
        Ok(())
    }

    /// 确认密码重置：消费一次性 token → 设置新密码（Argon2id）
    /// → 吊销全部会话（防止重置前的旧会话继续有效）。
    pub async fn confirm_password_reset(
        &self,
        raw_token: &str,
        new_password: &str,
        client_ip: &str,
    ) -> Result<(), UserError> {
        self.validate_password_len(new_password)?;
        let token_hash = hash_refresh_token(raw_token);
        let (_, purpose, user_id) = self
            .email_verifications
            .consume_by_hash(&token_hash)
            .await?
            .ok_or(UserError::InvalidRefreshToken)?;
        if purpose != VerificationPurpose::PasswordReset {
            return Err(UserError::InvalidRefreshToken);
        }
        let Some(user_id) = user_id else {
            return Err(UserError::InvalidRefreshToken);
        };
        let new_hash = hash_password(new_password)?;
        self.repo.update_password_hash(user_id, &new_hash).await?;
        self.refresh.revoke_all_for_user(user_id).await?;
        self.audit(Some(user_id), AuditAction::PasswordChanged, "password_reset", client_ip).await;
        Ok(())
    }

    /// 码通道确认密码重置：App 端填 6 位码。语义同 confirm_password_reset，
    /// 另校验码所属邮箱与请求邮箱一致（防跨账号用码）。
    pub async fn confirm_password_reset_code(
        &self,
        email: &str,
        code: &str,
        new_password: &str,
        client_ip: &str,
    ) -> Result<(), UserError> {
        self.validate_password_len(new_password)?;
        let token_hash = hash_refresh_token(code);
        let (verified_email, purpose, user_id) = self
            .email_verifications
            .consume_by_hash(&token_hash)
            .await?
            .ok_or(UserError::InvalidRefreshToken)?;
        if purpose != VerificationPurpose::PasswordReset
            || !verified_email.eq_ignore_ascii_case(email)
        {
            return Err(UserError::InvalidRefreshToken);
        }
        let Some(user_id) = user_id else {
            return Err(UserError::InvalidRefreshToken);
        };
        let new_hash = hash_password(new_password)?;
        self.repo.update_password_hash(user_id, &new_hash).await?;
        self.refresh.revoke_all_for_user(user_id).await?;
        self.audit(Some(user_id), AuditAction::PasswordChanged, "password_reset_code", client_ip).await;
        Ok(())
    }
}

/// 密码重置邮件 HTML 模板：按配置渲染 码 / PC 链接 / App deep link 段。
impl UserService {
    fn password_reset_email_html(&self, username: &str, code: &str, link: &str) -> String {
        use super::email_creds;
        let channels = &self.config.email_channels;
        let mut parts: Vec<String> = Vec::new();
        if let Some(block) = email_creds::code_block(channels, code) {
            parts.push(format!(
                r#"  <p>你请求重置账号密码。在应用中输入此验证码设置新密码（15 分钟内有效，仅可使用一次）：</p>
{block}"#
            ));
        }
        if let Some(block) = email_creds::pc_link_block(channels, link, "重置密码") {
            parts.push(block);
        }
        if let Some(block) = email_creds::app_link_block(channels, "password-reset", "重置密码") {
            parts.push(block);
        }
        if parts.is_empty() {
            parts.push(format!(
                r#"  <p>你请求重置账号密码，请点击下面的链接设置新密码：</p>
  <p><a href="{link}">{link}</a></p>"#,
                link = link
            ));
        }
        format!(
            r#"<div style="font-family:sans-serif;max-width:480px;margin:0 auto">
  <h2>你好，{username}</h2>
{parts}
  <p style="color:#888;font-size:13px">重置成功后，你之前的所有登录会话将被吊销。</p>
  <p style="color:#888;font-size:13px">如果你没有请求重置密码，请忽略本邮件，你的密码不会被更改。</p>
</div>"#,
            username = username,
            parts = email_creds::join(parts)
        )
    }
}
