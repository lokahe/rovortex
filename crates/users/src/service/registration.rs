//! 注册用例：legacy register + 不建号式双通道注册（码/链接）。

use uuid::Uuid;

use super::{
    Session, SessionContext, UserService,
    token_utils::{generate_refresh_token, hash_refresh_token},
};
use crate::audit::AuditAction;
use crate::domain::{NewUser, UserError, validate_email, validate_username};
use crate::email_verification::{NewEmailVerification, VerificationPurpose};
use crate::password::hash_password;

impl UserService {
    /// 注册：校验 → 查重 → Argon2id 哈希 → 持久化 → 签发会话。
    ///
    /// `username` 可空：None 时由邮箱前缀自动生成（冲突加数字后缀），用户后续
    /// 可通过 PUT /me/username 修改；Some 时仍做格式校验与唯一性检查（409）。
    pub async fn register(
        &self,
        username: Option<&str>,
        email: &str,
        password: &str,
        client_ip: &str,
        ctx: &SessionContext,
    ) -> Result<Session, UserError> {
        validate_email(email)?;
        self.validate_password_len(password)?;

        // 预检查提升常见错误的可读性；真正的唯一性仍由仓储层保证（数据库唯一索引）。
        if let Some(name) = username {
            validate_username(name)?;
            if self.repo.find_by_username(name).await?.is_some() {
                return Err(UserError::UsernameTaken(name.into()));
            }
        }
        if self.repo.find_by_email(email).await?.is_some() {
            return Err(UserError::EmailTaken(email.into()));
        }

        let password_hash = hash_password(password)?;
        let username = match username {
            Some(name) => name.to_string(),
            None => self.unique_username_from(email, None).await?,
        };
        let user = self
            .repo
            .create(NewUser {
                username,
                email: email.into(),
                password_hash: Some(password_hash),
            })
            .await?;
        self.audit(
            Some(user.id),
            AuditAction::Register,
            format!("username={}", user.username),
            client_ip,
        )
        .await;
        self.issue_session(user, ctx).await
    }

    /// 发起邮箱注册验证：不建号，发双通道验证邮件（6 位验证码 + 确认链接）。
    ///
    /// 账号在验证成功（confirm_code / confirm_link）时才创建——错邮箱零残留，
    /// 未验证账号从未有过会话。两条通道各持一条一次性记录，任一成功即可。
    /// 防枚举：邮箱已注册则不发信但恒 Ok。发信失败不阻断（可重发），只记录。
    pub async fn request_signup(&self, email: &str, client_ip: &str) -> Result<(), UserError> {
        validate_email(email)?;
        if self.repo.find_by_email(email).await?.is_some() {
            return Ok(()); // 已注册：防枚举，不发信
        }
        self.audit(
            None,
            AuditAction::SignupRequested,
            format!("email={email}"),
            client_ip,
        )
        .await;

        let expires_at =
            chrono::Utc::now() + chrono::Duration::minutes(self.config.email_verification_ttl_mins);
        // 通道一：6 位数字验证码（App 内手动回填）
        let code = Self::generate_signup_code();
        // 通道二：确认链接（PC 浏览器完成注册）
        let link_token = generate_refresh_token();
        for raw in [&code, &link_token] {
            self.email_verifications
                .insert(NewEmailVerification {
                    id: Uuid::now_v7(),
                    email: email.to_string(),
                    token_hash: hash_refresh_token(raw),
                    purpose: VerificationPurpose::Signup,
                    user_id: None,
                    expires_at,
                })
                .await?;
        }
        let link = format!(
            "{}/api/auth/signup/confirm?token={}",
            self.verify_url_base, link_token
        );
        let html = self.signup_email_html(email, &code, &link);
        if let Err(e) = self.mail.send(email, "Rovortex 注册验证", &html).await {
            tracing::warn!(email, error = %e, "failed to send signup email");
        }
        Ok(())
    }

    /// 验证码通道确认注册：码 + 密码（App 暂存回传）→ 建号 + 会话。
    ///
    /// 建号即视为邮箱已验证（收码权即邮箱归属证明）。限流由表现层实施。
    pub async fn confirm_signup_code(
        &self,
        email: &str,
        code: &str,
        password: &str,
        username: Option<&str>,
        client_ip: &str,
        ctx: &SessionContext,
    ) -> Result<Session, UserError> {
        let (verified_email, _purpose, _) = self
            .email_verifications
            .consume_by_hash(&hash_refresh_token(code))
            .await?
            .ok_or(UserError::InvalidSignupCode)?;
        if _purpose != VerificationPurpose::Signup || !verified_email.eq_ignore_ascii_case(email) {
            return Err(UserError::InvalidSignupCode);
        }
        self.create_verified_user(&verified_email, password, username, client_ip, ctx)
            .await
    }

    /// 链接通道确认注册：PC 浏览器表单提交（token + 密码）→ 建号。
    pub async fn confirm_signup_link(
        &self,
        raw_token: &str,
        password: &str,
        client_ip: &str,
        ctx: &SessionContext,
    ) -> Result<Session, UserError> {
        let (email, purpose, _) = self
            .email_verifications
            .consume_by_hash(&hash_refresh_token(raw_token))
            .await?
            .ok_or(UserError::InvalidSignupCode)?;
        if purpose != VerificationPurpose::Signup {
            return Err(UserError::InvalidSignupCode);
        }
        self.create_verified_user(&email, password, None, client_ip, ctx)
            .await
    }

    /// 建号（邮箱已验证语义）：密码/用户名校验 + 唯一性检查 + email_verified=true。
    /// 并发撞车由仓储层唯一索引兜底。
    pub(super) async fn create_verified_user(
        &self,
        email: &str,
        password: &str,
        username: Option<&str>,
        client_ip: &str,
        ctx: &SessionContext,
    ) -> Result<Session, UserError> {
        self.validate_password_len(password)?;
        if let Some(name) = username {
            validate_username(name)?;
            if self.repo.find_by_username(name).await?.is_some() {
                return Err(UserError::UsernameTaken(name.into()));
            }
        }
        if self.repo.find_by_email(email).await?.is_some() {
            return Err(UserError::EmailTaken(email.into()));
        }
        let password_hash = hash_password(password)?;
        let username = match username {
            Some(name) => name.to_string(),
            None => self.unique_username_from(email, None).await?,
        };
        let mut user = self
            .repo
            .create(NewUser {
                username,
                email: email.into(),
                password_hash: Some(password_hash),
            })
            .await?;
        self.repo.mark_email_verified(user.id).await?;
        user.email_verified = true;
        self.audit(
            Some(user.id),
            AuditAction::Register,
            format!("username={} verified=true", user.username),
            client_ip,
        )
        .await;
        self.issue_session(user, ctx).await
    }

    /// 生成 6 位数字注册验证码（字符串形式；哈希后落 email_verifications）。
    pub(super) fn generate_signup_code() -> String {
        use rand_core::{OsRng, RngCore};
        // 6 位数字空间 10^6；confirm 端点限流（表现层）使爆破不可行。
        format!("{:06}", OsRng.next_u32() % 1_000_000)
    }

    /// 注册验证邮件 HTML 模板：按配置渲染 码 / PC 链接 / App deep link 段。
    fn signup_email_html(&self, email: &str, code: &str, link: &str) -> String {
        use super::email_creds;
        let channels = &self.config.email_channels;
        let mut parts: Vec<String> = Vec::new();
        if let Some(block) = email_creds::code_block(channels, code) {
            parts.push(format!(
                r#"  <p>你好 {email}，你的注册验证码（15 分钟内有效）：</p>
{block}
  <p style="color:#555">在应用中输入此验证码即可完成注册。</p>"#,
                email = email,
                block = block
            ));
        }
        if let Some(block) = email_creds::pc_link_block(channels, link, "在浏览器中完成注册")
        {
            parts.push(block);
        }
        if let Some(block) = email_creds::app_link_block(channels, "signup", "完成注册") {
            parts.push(block);
        }
        // 全关时兜底：至少给出 PC 链接文本（组合根保证不会发生，防御测试外的意外配置）。
        if parts.is_empty() {
            parts.push(format!(
                r#"  <p>你好 {email}，请点击下面的链接完成注册：</p>
  <p><a href="{link}">{link}</a></p>"#,
                email = email,
                link = link
            ));
        }
        format!(
            r#"<div style="font-family:sans-serif;max-width:480px;margin:0 auto">
  <h2>注册 Rovortex</h2>
{parts}
  <p style="color:#888;font-size:13px">如果你没有注册过 Rovortex，请忽略本邮件。</p>
</div>"#,
            parts = email_creds::join(parts)
        )
    }
}
