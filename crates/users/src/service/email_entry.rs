//! 统一邮箱入口：邮箱+密码一框登录/注册（设计见 docs/EMAIL_ENTRY.md）。
//!
//! 防枚举核心：request 响应只有 200（凭据有效）与 202（其余一切）两种；
//! 每个被提交的合法邮箱都"发信"（封禁/注销/限流时走哑路径保持时序一致）。
//! confirm 语义：已注册 → 码即登录凭据 + 静默设密；未注册 → 建号。

use uuid::Uuid;

use super::{Session, SessionContext, UserService, hash_refresh_token};
use crate::audit::AuditAction;
use crate::domain::{UserError, validate_email};
use crate::email_verification::{NewEmailVerification, VerificationPurpose};
use crate::password::{hash_password, verify_password};
use crate::rate_limit::guard_key;

impl UserService {
    /// 统一入口 request：
    /// - 已注册 + 密码对 → 直接签发会话（唯一 200 出口）
    /// - 已注册 + 密码错 / 无密码 → 发 EmailEntry 码邮件（收码登录+静默设密）
    /// - 未注册（含冷静期外的注销号）→ 发 EmailEntry 码邮件（收码+密码建号）
    /// - 封禁 / 冷静期内注销 → 不发信，走哑路径（响应仍 202 不可区分）
    ///
    /// `password` 为空视同无密码路径（OAuth 风格入口，走哑 argon2 保时序）。
    /// 密码错与 /api/users/login 共用同一把 login_guard（guard_key 同构）：
    /// 绕端点轰炸无意义（设计文档 §3 #21）。
    /// 邮件模板按 `platform` 取通道集（app=码+dp；web/pc=码+PC 链接）。
    pub async fn request_email_entry(
        &self,
        email: &str,
        password: &str,
        platform: &str,
        client_ip: &str,
        ctx: &SessionContext,
    ) -> Result<Option<Session>, UserError> {
        validate_email(email)?;
        let key = guard_key(client_ip, email);
        self.login_guard.check(&key).await?;
        let user = self.repo.find_by_email(email).await?;

        let Some(user) = user else {
            // 未注册：哑 argon2 后发码（建号在 confirm）。
            self.decoy_argon2();
            self.audit(
                None,
                AuditAction::SignupRequested,
                format!("email={email} entry"),
                client_ip,
            )
            .await;
            self.login_guard.record_success(&key).await;
            self.send_entry_code(email, platform).await?;
            return Ok(None);
        };

        // 封禁 / 冷静期内注销：不发信不登录，哑路径保时序，响应与发信分支一致。
        if user.status != 0 {
            self.decoy_argon2();
            self.login_guard.record_success(&key).await;
            return Ok(None);
        }

        match &user.password_hash {
            Some(hash) if !password.is_empty() => {
                if verify_password(password, hash) {
                    self.login_guard.record_success(&key).await;
                    self.audit(Some(user.id), AuditAction::LoginSuccess, "entry", client_ip)
                        .await;
                    return Ok(Some(self.issue_session(user, ctx).await?));
                }
                // 密码错：计入共享失败计数（与 login 同锁），然后发码。
                self.audit(
                    None,
                    AuditAction::LoginFailure,
                    format!("email={email} entry"),
                    client_ip,
                )
                .await;
                self.login_guard.record_failure(&key).await;
                self.send_entry_code(email, platform).await?;
                Ok(None)
            }
            _ => {
                // 已注册无密码（OAuth/魔法链建号）或入口未带密码：发码。
                self.login_guard.record_success(&key).await;
                self.send_entry_code(email, platform).await?;
                Ok(None)
            }
        }
    }

    /// 统一入口 confirm：
    /// - 已注册：码即登录凭据；带 password 则静默更新密码（收码=邮箱控制权，与 reset 同语义）。
    /// - 未注册：建号（email_verified=true），password 必填。
    pub async fn confirm_email_entry(
        &self,
        email: &str,
        code: &str,
        password: Option<&str>,
        client_ip: &str,
        ctx: &SessionContext,
    ) -> Result<Session, UserError> {
        let (verified_email, purpose, _user_id) = self
            .email_verifications
            .consume_by_hash(&hash_refresh_token(code))
            .await?
            .ok_or(UserError::InvalidSignupCode)?;
        if purpose != VerificationPurpose::EmailEntry || !verified_email.eq_ignore_ascii_case(email)
        {
            return Err(UserError::InvalidSignupCode);
        }
        match self.repo.find_by_email(&verified_email).await? {
            Some(user) => {
                // 收码后、confirm 前被封禁/注销：拒绝登录与设密。
                if user.status != 0 {
                    return Err(if user.status == super::BANNED_STATUS {
                        UserError::AccountBanned
                    } else {
                        UserError::AccountDeleted
                    });
                }
                if let Some(pwd) = password {
                    self.validate_password_len(pwd)?;
                    let new_hash = hash_password(pwd)?;
                    self.repo.update_password_hash(user.id, &new_hash).await?;
                    self.audit(
                        Some(user.id),
                        AuditAction::PasswordChanged,
                        "email_entry",
                        client_ip,
                    )
                    .await;
                } else {
                    self.audit(
                        Some(user.id),
                        AuditAction::LoginSuccess,
                        "entry_code",
                        client_ip,
                    )
                    .await;
                }
                // 重新查一遍拿最新 status/password 语义（update 后 user 已陈旧仅用于 id）。
                self.issue_session(user, ctx).await
            }
            None => {
                let pwd = password.ok_or(UserError::InvalidPassword(
                    "password required to create account".into(),
                ))?;
                self.create_verified_user(&verified_email, pwd, None, client_ip, ctx)
                    .await
            }
        }
    }

    /// 生成并投递 EmailEntry 码（码单通道记录；双记录的链接通道仅 web/pc 需要，暂缓）。
    async fn send_entry_code(&self, email: &str, platform: &str) -> Result<(), UserError> {
        let code = Self::generate_signup_code();
        self.email_verifications
            .insert(NewEmailVerification {
                id: Uuid::now_v7(),
                email: email.to_string(),
                token_hash: hash_refresh_token(&code),
                purpose: VerificationPurpose::EmailEntry,
                user_id: None,
                expires_at: chrono::Utc::now()
                    + chrono::Duration::minutes(self.config.email_verification_ttl_mins),
            })
            .await?;
        // entry 码 dp 路径固定为 entry?code=...（app 平台）；模板按平台矩阵渲染。
        let channels = self.config.email_channels.for_platform(platform);
        let html = self.entry_email_html(&channels, &code);
        if let Err(e) = self.mail.send(email, "Rovortex 验证码", &html).await {
            tracing::warn!(email, error = %e, "failed to send entry email");
        }
        Ok(())
    }

    /// 哑 argon2：未注册/封禁/注销路径跑一次等价哈希，抹平验密码的耗时差。
    fn decoy_argon2(&self) {
        let _ = verify_password(
            "decoy-password-for-timing",
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$GXu7C2VZJceJFbRHTpnLZaGNdSui3SSueQFYFFtWDh0",
        );
    }

    /// 统一入口邮件模板：中性文案（不说"注册"也不说"登录"），按平台矩阵渲染凭据段。
    /// app 平台 = 码 + dp（rovortex://entry?code=...）；web/pc = 码（PC 链接待网页端开发时加）。
    fn entry_email_html(&self, channels: &super::EmailChannels, code: &str) -> String {
        use super::email_creds;
        let mut parts: Vec<String> = Vec::new();
        if let Some(block) = email_creds::code_block(channels, code) {
            parts.push(format!(
                r#"  <p>输入此验证码继续（15 分钟内有效，仅可使用一次）：</p>
{block}"#
            ));
        }
        if let Some(block) =
            email_creds::app_link_block(channels, &format!("entry?code={code}"), "继续")
        {
            parts.push(block);
        }
        if parts.is_empty() {
            // 兜底：码通道被全局关闭时仍给出码文本（entry 没有码就无法 confirm）。
            parts.push(format!(r#"  <p>验证码：{code}</p>"#));
        }
        format!(
            r#"<div style="font-family:sans-serif;max-width:480px;margin:0 auto">
  <h2>Rovortex</h2>
{parts}
  <p style="color:#888;font-size:13px">如果你没有尝试使用 Rovortex，请忽略本邮件。</p>
</div>"#,
            parts = email_creds::join(parts)
        )
    }
}
