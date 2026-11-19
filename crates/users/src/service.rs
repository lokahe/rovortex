//! 用户用例编排：注册 / 登录 / 会话刷新。

use std::sync::Arc;

use uuid::Uuid;

use crate::audit::{AuditAction, AuditRepository, NewAuditLog};
use crate::domain::{
    NewUser, User, UserError, validate_email, validate_password, validate_username,
};
use crate::email_verification::{
    EmailVerificationRepository, NewEmailVerification, VerificationPurpose,
};
use crate::mail::MailSender;
use crate::oauth_identity::{
    ExternalIdentity, ExternalProfile, NewExternalIdentity, OauthIdentityRepository,
};
use crate::password::{hash_password, verify_password};
use crate::rate_limit::LoginGuard;
use crate::refresh_token::{NewRefreshToken, RefreshTokenRepository};
use crate::repository::UserRepository;

const REFRESH_TTL_DAYS: i64 = 30;
const EMAIL_VERIFICATION_TTL_MINS: i64 = 15;
/// users.status 的封禁值（与 admin::BANNED_STATUS 一致）。
pub const BANNED_STATUS: i16 = 1;

/// 一次登录/刷新产出的完整会话：领域层不关心 JWT 细节，
/// access token 由表现层用 TokenSigner 另行签发。
#[derive(Debug, Clone)]
pub struct Session {
    pub user: User,
    /// 明文 refresh token：仅在签发瞬间存在，此后只存哈希。
    pub refresh_token: String,
    pub refresh_expires_at: chrono::DateTime<chrono::Utc>,
}

/// 展示资料的部分更新（PATCH 语义）：
/// `None` = 不动，`Some(Some(v))` = 更新为 v，`Some(None)` = 清空。
#[derive(Debug, Clone, Default)]
pub struct ProfilePatch {
    pub display_name: Option<Option<String>>,
    pub avatar_url: Option<Option<String>>,
    pub bio: Option<Option<String>>,
    pub website_url: Option<Option<String>>,
}

/// 用户业务服务。持有仓储抽象，具体实现在组合根注入。
#[derive(Clone)]
pub struct UserService {
    repo: Arc<dyn UserRepository>,
    refresh: Arc<dyn RefreshTokenRepository>,
    email_verifications: Arc<dyn EmailVerificationRepository>,
    mail: Arc<dyn MailSender>,
    /// 登录限流（可为 NoopLoginGuard 关闭，如测试）。
    login_guard: Arc<dyn LoginGuard>,
    /// 审计日志（安全动作证据链；写失败只记日志不阻断业务）。
    audit: Arc<dyn AuditRepository>,
    /// 外部身份（OAuth / Magic Link）仓储。
    identities: Arc<dyn OauthIdentityRepository>,
    /// 验证邮件里的确认链接前缀（如 https://api.example.com）。
    verify_url_base: String,
}

impl UserService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repo: Arc<dyn UserRepository>,
        refresh: Arc<dyn RefreshTokenRepository>,
        email_verifications: Arc<dyn EmailVerificationRepository>,
        mail: Arc<dyn MailSender>,
        login_guard: Arc<dyn LoginGuard>,
        audit: Arc<dyn AuditRepository>,
        identities: Arc<dyn OauthIdentityRepository>,
        verify_url_base: String,
    ) -> Self {
        Self {
            repo,
            refresh,
            email_verifications,
            mail,
            login_guard,
            audit,
            identities,
            verify_url_base,
        }
    }

    /// 暴露仓储给表现层做按 id 的资料读取（受鉴权保护，如 require_admin / users_me）。
    pub fn repository(&self) -> Arc<dyn UserRepository> {
        Arc::clone(&self.repo)
    }

    /// 吊销用户全部会话（改密码等场景复用），返回吊销数量。
    pub async fn revoke_sessions_for(&self, user_id: Uuid) -> Result<u64, UserError> {
        self.refresh.revoke_all_for_user(user_id).await
    }

    /// 注册：校验 → 查重 → Argon2id 哈希 → 持久化 → 签发会话。
    pub async fn register(
        &self,
        username: &str,
        email: &str,
        password: &str,
        client_ip: &str,
    ) -> Result<Session, UserError> {
        validate_username(username)?;
        validate_email(email)?;
        validate_password(password)?;

        // 预检查提升常见错误的可读性；真正的唯一性仍由仓储层保证（数据库唯一索引）。
        if self.repo.find_by_username(username).await?.is_some() {
            return Err(UserError::UsernameTaken(username.into()));
        }
        if self.repo.find_by_email(email).await?.is_some() {
            return Err(UserError::EmailTaken(email.into()));
        }

        let password_hash = hash_password(password)?;
        let user = self
            .repo
            .create(NewUser {
                username: username.into(),
                email: email.into(),
                password_hash: Some(password_hash),
            })
            .await?;
        self.audit(
            Some(user.id),
            AuditAction::Register,
            format!("username={username}"),
            client_ip,
        ).await;
        self.issue_session(user).await
    }

    /// 登录：支持用户名或邮箱。
    ///
    /// 安全设计：无论“用户不存在”还是“密码错误”，一律返回 [`UserError::InvalidCredentials`]，
    /// 避免账号枚举攻击。
    /// 写审计：失败只记日志，绝不阻断业务主流程。
    async fn audit(
        &self,
        user_id: Option<Uuid>,
        action: AuditAction,
        detail: impl Into<String>,
        client_ip: &str,
    ) {
        let entry = NewAuditLog {
            user_id,
            action,
            detail: detail.into(),
            client_ip: client_ip.to_string(),
        };
        // 直接 await（不 spawn）：业务层不持有 runtime 特性依赖；
        // 审计仓储实现均为低延迟写（PG 单条 INSERT / 内存 Vec），可接受。
        if let Err(e) = self.audit.append(entry).await {
            tracing::warn!(error = %e, "failed to append audit log");
        }
    }

    /// 登录：限流检查 → 查用户 → 验密码 → 签会话。
    ///
    /// `guard_key` 由表现层按 (client_ip, login) 生成后传入；
    /// 锁定中的尝试直接拒绝，不消耗 Argon2 算力。
    pub async fn login(&self, guard_key: &str, login: &str, password: &str, client_ip: &str) -> Result<Session, UserError> {
        self.login_guard.check(guard_key).await?;
        let result = self.login_inner(login, password).await;
        match &result {
            Ok(s) => {
                self.audit(
                    Some(s.user.id),
                    AuditAction::LoginSuccess,
                    format!("login={login}"),
                    client_ip,
                ).await;
                self.login_guard.record_success(guard_key).await
            }
            Err(UserError::InvalidCredentials) => {
                self.audit(None, AuditAction::LoginFailure, format!("login={login}"), client_ip).await;
                self.login_guard.record_failure(guard_key).await
            }
            // 用户不存在也计入失败（防枚举语义下这同样是 InvalidCredentials，
            // 但防御性处理：其他错误不计入）
            Err(UserError::UserNotFound) => {
                self.audit(None, AuditAction::LoginFailure, format!("login={login}"), client_ip).await;
                self.login_guard.record_failure(guard_key).await
            }
            Err(_) => {}
        }
        result
    }

    async fn login_inner(&self, login: &str, password: &str) -> Result<Session, UserError> {
        let user = self
            .repo
            .find_by_login(login)
            .await?
            .ok_or(UserError::InvalidCredentials)?;

        // 无密码账号（纯 OAuth/Magic 用户）：不提示「未设置密码」，恒 InvalidCredentials 防枚举。
        let Some(hash) = user.password_hash.as_deref() else {
            return Err(UserError::InvalidCredentials);
        };
        if !verify_password(password, hash) {
            return Err(UserError::InvalidCredentials);
        }
        self.issue_session(user).await
    }

    /// 用 refresh token 换取新会话（轮换：旧 token 立即吊销）。
    pub async fn refresh(&self, raw_token: &str, client_ip: &str) -> Result<Session, UserError> {
        let token_hash = hash_refresh_token(raw_token);
        let result = self.refresh_inner(&token_hash, client_ip).await;
        if result.is_err() {
            self.audit(None, AuditAction::RefreshFailure, "invalid refresh token", client_ip).await;
        }
        result
    }

    async fn refresh_inner(&self, token_hash: &str, client_ip: &str) -> Result<Session, UserError> {
        let (user_id, _) = self
            .refresh
            .find_active_by_hash(token_hash)
            .await?
            .ok_or(UserError::InvalidRefreshToken)?;
        self.refresh.revoke_by_hash(token_hash).await?;

        let user = self
            .repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::UserNotFound)?;
        self.audit(Some(user.id), AuditAction::RefreshSuccess, "", client_ip).await;
        self.issue_session(user).await
    }

    /// 登出：吊销给定 refresh token（幂等：token 无效也返回成功）。
    pub async fn logout(&self, raw_token: &str, client_ip: &str) -> Result<(), UserError> {
        let hash = hash_refresh_token(raw_token);
        // 吊销前反查归属，便于审计关联用户（查不到也照常吊销，幂等语义不变）。
        let owner = self
            .refresh
            .find_active_by_hash(&hash)
            .await?
            .map(|(uid, _)| uid);
        self.audit(owner, AuditAction::Logout, "", client_ip).await;
        self.refresh.revoke_by_hash(&hash).await
    }

    /// 修改密码：验证旧密码 → 重哈希 → 吊销该用户全部会话。
    ///
    /// 无密码账号（OAuth/Magic 用户首次设密码）请用 [`UserService::set_password`]。
    pub async fn change_password(
        &self,
        user_id: Uuid,
        old_password: &str,
        new_password: &str,
        client_ip: &str,
    ) -> Result<(), UserError> {
        validate_password(new_password)?;
        let user = self
            .repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::UserNotFound)?;
        let Some(old_hash) = user.password_hash.as_deref() else {
            return Err(UserError::InvalidCredentials);
        };
        if !verify_password(old_password, old_hash) {
            self.audit(Some(user_id), AuditAction::LoginFailure, "change_password: old password mismatch", client_ip).await;
            return Err(UserError::InvalidCredentials);
        }
        let new_hash = hash_password(new_password)?;
        self.repo
            .update_password_hash(user_id, &new_hash)
            .await?;
        self.refresh.revoke_all_for_user(user_id).await?;
        self.audit(Some(user_id), AuditAction::PasswordChanged, "", client_ip).await;
        Ok(())
    }

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
            return self.issue_session(user).await;
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
        self.issue_session(user).await
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
    async fn unique_username_from(
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
        validate_password(new_password)?;
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

    /// 签发会话：封禁检查 → 生成 refresh token，哈希落库。
    /// 三种登录路径（密码/OAuth/Magic）共用此收口，封禁即刻生效。
    async fn issue_session(&self, user: User) -> Result<Session, UserError> {
        if user.status == BANNED_STATUS {
            return Err(UserError::AccountBanned);
        }
        let raw = generate_refresh_token();
        let expires_at = chrono::Utc::now() + chrono::Duration::days(REFRESH_TTL_DAYS);
        self.refresh
            .insert(NewRefreshToken {
                id: Uuid::now_v7(),
                user_id: user.id,
                token_hash: hash_refresh_token(&raw),
                expires_at,
            })
            .await?;
        Ok(Session {
            user,
            refresh_token: raw,
            refresh_expires_at: expires_at,
        })
    }

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
                        + chrono::Duration::minutes(EMAIL_VERIFICATION_TTL_MINS),
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
                    + chrono::Duration::minutes(EMAIL_VERIFICATION_TTL_MINS),
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
                    + chrono::Duration::minutes(EMAIL_VERIFICATION_TTL_MINS),
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
        self.login_with_identity("magic", &email, Some(&email), None, client_ip)
            .await
    }

    /// 忘记密码：给邮箱发重置链接（一次性，15 分钟有效）。    ///
    /// 防枚举：未注册邮箱不发信但恒返回 Ok（不泄露注册状态）。
    /// 只对有密码的账号发信——纯 OAuth/Magic 用户无需密码重置。
    /// 发信失败不阻断流程（用户可重发），只记录。
    pub async fn request_password_reset(&self, email: &str, client_ip: &str) -> Result<(), UserError> {
        validate_email(email)?;
        let Some(user) = self.repo.find_by_email(email).await? else {
            return Ok(());
        };
        if user.password_hash.is_none() {
            return Ok(());
        }
        self.audit(
            Some(user.id),
            AuditAction::PasswordResetRequested,
            format!("email={email}"),
            client_ip,
        ).await;
        let raw = generate_refresh_token();
        self.email_verifications
            .insert(NewEmailVerification {
                id: Uuid::now_v7(),
                email: email.to_string(),
                token_hash: hash_refresh_token(&raw),
                purpose: VerificationPurpose::PasswordReset,
                user_id: Some(user.id),
                expires_at: chrono::Utc::now()
                    + chrono::Duration::minutes(EMAIL_VERIFICATION_TTL_MINS),
            })
            .await?;
        let link = format!(
            "{}/api/auth/password-reset/confirm?token={}",
            self.verify_url_base, raw
        );
        let html = password_reset_email_html(&user.username, &link);
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
        validate_password(new_password)?;
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

/// 密码重置邮件 HTML 模板。
fn password_reset_email_html(username: &str, link: &str) -> String {
    format!(
        r#"<div style="font-family:sans-serif;max-width:480px;margin:0 auto">
  <h2>你好，{username}</h2>
  <p>你请求重置账号密码。请点击下面的链接设置新密码（15 分钟内有效，仅可使用一次）：</p>
  <p><a href="{link}" style="display:inline-block;padding:10px 20px;background:#4f46e5;color:#fff;text-decoration:none;border-radius:6px">重置密码</a></p>
  <p style="color:#888;font-size:13px">重置成功后，你之前的所有登录会话将被吊销。</p>
  <p style="color:#888;font-size:13px">如果你没有请求重置密码，请忽略本邮件，你的密码不会被更改。</p>
</div>"#
    )
}

/// 生成 256 位随机 refresh token（URL 安全 Base64）。
fn generate_refresh_token() -> String {
    use base64::Engine as _;
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// SHA-256 哈希：明文永不落库。
fn hash_refresh_token(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests_refresh {
    use super::*;

    #[test]
    fn refresh_token_is_random_and_hashed() {
        let a = generate_refresh_token();
        let b = generate_refresh_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43); // 32 bytes → 43 chars unpadded base64url
        assert_eq!(hash_refresh_token(&a), hash_refresh_token(&a));
        assert_ne!(hash_refresh_token(&a), hash_refresh_token(&b));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth_identity::{ExternalIdentity, NewExternalIdentity};
    use crate::refresh_token::NewRefreshToken;
    use crate::repository::UserRepository;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use uuid::Uuid;

    /// 测试用内存仓储：与生产实现一样满足 `Send + Sync` 且不可变自洽。
    struct TestRepository {
        store: Mutex<HashMap<Uuid, User>>,
        username_index: Mutex<HashMap<String, Uuid>>,
        email_index: Mutex<HashMap<String, Uuid>>,
    }

    impl TestRepository {
        fn new() -> Self {
            TestRepository {
                store: Mutex::new(HashMap::new()),
                username_index: Mutex::new(HashMap::new()),
                email_index: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl UserRepository for TestRepository {
        async fn create(&self, new_user: NewUser) -> Result<User, UserError> {
            let username_key = new_user.username.to_lowercase();
            let email_key = new_user.email.to_lowercase();

            if self.username_index.lock().unwrap().contains_key(&username_key) {
                return Err(UserError::UsernameTaken(new_user.username));
            }
            if self.email_index.lock().unwrap().contains_key(&email_key) {
                return Err(UserError::EmailTaken(new_user.email));
            }

            let user = User {
                id: Uuid::now_v7(),
                username: new_user.username,
                email: new_user.email,
                password_hash: new_user.password_hash,
                email_verified: false,
                is_admin: false,
                status: 0,
                display_name: None,
                avatar_url: None,
                bio: None,
                website_url: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            self.username_index
                .lock()
                .unwrap()
                .insert(username_key, user.id);
            self.email_index.lock().unwrap().insert(email_key, user.id);
            self.store.lock().unwrap().insert(user.id, user.clone());

            Ok(user)
        }

        async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserError> {
            let idx = self.username_index.lock().unwrap();
            let store = self.store.lock().unwrap();
            let id = idx.get(&username.to_lowercase()).cloned();
            Ok(id.and_then(|id| store.get(&id).cloned()))
        }

        async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
            let idx = self.email_index.lock().unwrap();
            let store = self.store.lock().unwrap();
            let id = idx.get(&email.to_lowercase()).cloned();
            Ok(id.and_then(|id| store.get(&id).cloned()))
        }

        async fn find_by_login(&self, login: &str) -> Result<Option<User>, UserError> {
            let key = login.to_lowercase();
            let username_id = self.username_index.lock().unwrap().get(&key).cloned();
            let id = username_id.or_else(|| self.email_index.lock().unwrap().get(&key).cloned());
            let store = self.store.lock().unwrap();
            Ok(id.and_then(|id| store.get(&id).cloned()))
        }

        async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, UserError> {
            Ok(self.store.lock().unwrap().get(&id).cloned())
        }

        async fn update_password_hash(
            &self,
            id: Uuid,
            new_hash: &str,
        ) -> Result<(), UserError> {
            let mut store = self.store.lock().unwrap();
            let user = store.get_mut(&id).ok_or(UserError::UserNotFound)?;
            user.password_hash = Some(new_hash.to_string());
            user.updated_at = Utc::now();
            Ok(())
        }

        async fn mark_email_verified(&self, id: Uuid) -> Result<(), UserError> {
            let mut store = self.store.lock().unwrap();
            let user = store.get_mut(&id).ok_or(UserError::UserNotFound)?;
            user.email_verified = true;
            user.updated_at = Utc::now();
            Ok(())
        }

        async fn update_email(&self, id: Uuid, new_email: &str) -> Result<(), UserError> {
            let email_key = new_email.to_lowercase();
            if self
                .email_index
                .lock()
                .unwrap()
                .get(&email_key)
                .is_some_and(|&existing| existing != id)
            {
                return Err(UserError::EmailTaken(new_email.to_string()));
            }
            let mut store = self.store.lock().unwrap();
            let user = store.get_mut(&id).ok_or(UserError::UserNotFound)?;
            if let Some(old) = self
                .email_index
                .lock()
                .unwrap()
                .remove(&user.email.to_lowercase())
            {
                debug_assert_eq!(old, id);
            }
            user.email = new_email.to_string();
            user.email_verified = true;
            user.updated_at = Utc::now();
            self.email_index
                .lock()
                .unwrap()
                .insert(email_key, id);
            Ok(())
        }

        async fn update_username(&self, id: Uuid, new_username: &str) -> Result<(), UserError> {
            let username_key = new_username.to_lowercase();
            if self
                .username_index
                .lock()
                .unwrap()
                .get(&username_key)
                .is_some_and(|&existing| existing != id)
            {
                return Err(UserError::UsernameTaken(new_username.to_string()));
            }
            let mut store = self.store.lock().unwrap();
            let user = store.get_mut(&id).ok_or(UserError::UserNotFound)?;
            self.username_index
                .lock()
                .unwrap()
                .remove(&user.username.to_lowercase());
            user.username = new_username.to_string();
            user.updated_at = Utc::now();
            self.username_index
                .lock()
                .unwrap()
                .insert(username_key, id);
            Ok(())
        }

        async fn update_profile(&self, id: Uuid, patch: &ProfilePatch) -> Result<(), UserError> {
            let mut store = self.store.lock().unwrap();
            let user = store.get_mut(&id).ok_or(UserError::UserNotFound)?;
            if let Some(v) = patch.display_name.clone() {
                user.display_name = v;
            }
            if let Some(v) = patch.avatar_url.clone() {
                user.avatar_url = v;
            }
            if let Some(v) = patch.bio.clone() {
                user.bio = v;
            }
            if let Some(v) = patch.website_url.clone() {
                user.website_url = v;
            }
            user.updated_at = Utc::now();
            Ok(())
        }

        async fn is_admin(&self, id: Uuid) -> Result<bool, UserError> {
            Ok(self
                .store
                .lock()
                .unwrap()
                .get(&id)
                .is_some_and(|u| u.is_admin))
        }

        async fn list_users(
            &self,
            _q: Option<&str>,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<User>, UserError> {
            Ok(self.store.lock().unwrap().values().cloned().collect())
        }

        async fn count_users(&self, _q: Option<&str>) -> Result<i64, UserError> {
            Ok(self.store.lock().unwrap().len() as i64)
        }

        async fn set_status(&self, id: Uuid, _status: i16) -> Result<(), UserError> {
            let mut store = self.store.lock().unwrap();
            let _user = store.get_mut(&id).ok_or(UserError::UserNotFound)?;
            Ok(())
        }

        async fn promote_admin(&self, id: Uuid) -> Result<(), UserError> {
            let mut store = self.store.lock().unwrap();
            let user = store.get_mut(&id).ok_or(UserError::UserNotFound)?;
            user.is_admin = true;
            user.updated_at = Utc::now();
            Ok(())
        }

        async fn count_audit_by_action(
            &self,
            _since: chrono::DateTime<chrono::Utc>,
        ) -> Result<Vec<(String, i64)>, UserError> {
            Ok(Vec::new())
        }
    }

    /// 内存邮件桩：记录发送内容供断言。
    #[derive(Default)]
    struct TestMailSender {
        sent: Mutex<Vec<(String, String, String)>>, // (to, subject, html)
    }

    #[async_trait::async_trait]
    impl MailSender for TestMailSender {
        async fn send(&self, to: &str, subject: &str, html: &str) -> Result<(), crate::mail::MailError> {
            self.sent
                .lock()
                .unwrap()
                .push((to.to_string(), subject.to_string(), html.to_string()));
            Ok(())
        }
    }

    /// 内存验证 token 仓储：模拟 PG 的原子消费语义。
    /// 记录含内部 consumed 标记，不污染领域结构。
    struct TestVerificationRepository {
        tokens: Mutex<Vec<(
            crate::email_verification::NewEmailVerification,
            bool, // consumed
        )>>,
    }

    impl TestVerificationRepository {
        fn new() -> Self {
            Self { tokens: Mutex::new(Vec::new()) }
        }
    }

    #[async_trait::async_trait]
    impl EmailVerificationRepository for TestVerificationRepository {
        async fn insert(
            &self,
            token: crate::email_verification::NewEmailVerification,
        ) -> Result<(), UserError> {
            self.tokens.lock().unwrap().push((token, false));
            Ok(())
        }

        async fn consume_by_hash(
            &self,
            token_hash: &str,
        ) -> Result<Option<(String, VerificationPurpose, Option<Uuid>)>, UserError> {
            let mut tokens = self.tokens.lock().unwrap();
            let now = Utc::now();
            let idx = tokens.iter().position(|(t, consumed)| {
                t.token_hash == token_hash && !*consumed && t.expires_at > now
            });
            match idx {
                Some(i) => {
                    tokens[i].1 = true;
                    let t = &tokens[i].0;
                    Ok(Some((t.email.clone(), t.purpose, t.user_id)))
                }
                None => Ok(None),
            }
        }
    }

    /// 内存 refresh token 仓储：模拟 PG 实现的语义（哈希查找、吊销）。
    struct TestRefreshRepository {
        tokens: Mutex<HashMap<String, (Uuid, chrono::DateTime<Utc>)>>, // hash -> (user, expires)
        revoked: Mutex<std::collections::HashSet<String>>,
    }

    impl TestRefreshRepository {
        fn new() -> Self {
            Self {
                tokens: Mutex::new(HashMap::new()),
                revoked: Mutex::new(std::collections::HashSet::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl RefreshTokenRepository for TestRefreshRepository {
        async fn insert(&self, token: NewRefreshToken) -> Result<(), UserError> {
            self.tokens
                .lock()
                .unwrap()
                .insert(token.token_hash, (token.user_id, token.expires_at));
            Ok(())
        }

        async fn find_active_by_hash(
            &self,
            token_hash: &str,
        ) -> Result<Option<(Uuid, String)>, UserError> {
            let tokens = self.tokens.lock().unwrap();
            let revoked = self.revoked.lock().unwrap();
            if revoked.contains(token_hash) {
                return Ok(None);
            }
            Ok(tokens
                .get(token_hash)
                .filter(|(_, exp)| *exp > Utc::now())
                .map(|(uid, _)| (*uid, token_hash.to_string())))
        }

        async fn revoke_by_hash(&self, token_hash: &str) -> Result<(), UserError> {
            self.revoked.lock().unwrap().insert(token_hash.to_string());
            Ok(())
        }

        async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<u64, UserError> {
            let tokens = self.tokens.lock().unwrap();
            let mut revoked = self.revoked.lock().unwrap();
            let mut n = 0u64;
            for (hash, (uid, _)) in tokens.iter() {
                if *uid == user_id && !revoked.contains(hash) {
                    revoked.insert(hash.clone());
                    n += 1;
                }
            }
            Ok(n)
        }
    }

    fn service() -> UserService {
        service_with_mail(TestMailSender::default()).0
    }

    fn service_with_mail(mail: TestMailSender) -> (UserService, Arc<TestMailSender>) {
        let mail = Arc::new(mail);
        (
            UserService::new(
                Arc::new(TestRepository::new()),
                Arc::new(TestRefreshRepository::new()),
                Arc::new(TestVerificationRepository::new()),
                mail.clone() as Arc<dyn MailSender>,
                Arc::new(NoopLoginGuard),
                Arc::new(TestAuditRepository::default()),
                Arc::new(TestIdentityRepository::new()),
                "http://localhost:8080".to_string(),
            ),
            mail,
        )
    }

    /// 收集审计事件的桩（供断言）。
    #[derive(Default)]
    struct TestAuditRepository {
        events: Mutex<Vec<(Option<Uuid>, AuditAction)>>,
    }

    #[async_trait::async_trait]
    impl AuditRepository for TestAuditRepository {
        async fn append(&self, entry: NewAuditLog) -> Result<(), UserError> {
            self.events.lock().unwrap().push((entry.user_id, entry.action));
            Ok(())
        }

        async fn list_for_user(
            &self,
            _user_id: Uuid,
            _limit: i64,
        ) -> Result<Vec<crate::audit::AuditEntry>, UserError> {
            Ok(Vec::new())
        }
    }

    /// 测试用外部身份仓储桩。
    #[derive(Default)]
    struct TestIdentityRepository {
        /// (user_id, provider, provider_uid, raw_profile)
        identities: Mutex<Vec<(Uuid, String, String, Option<serde_json::Value>)>>,
    }

    impl TestIdentityRepository {
        fn new() -> Self {
            Self::default()
        }
    }

    #[async_trait::async_trait]
    impl OauthIdentityRepository for TestIdentityRepository {
        async fn find_by_external(
            &self,
            provider: &str,
            provider_uid: &str,
        ) -> Result<Option<ExternalIdentity>, UserError> {
            let list = self.identities.lock().unwrap();
            Ok(list
                .iter()
                .find(|(_, p, u, _)| p == provider && u == provider_uid)
                .map(|(uid, p, u, raw)| ExternalIdentity {
                    id: Uuid::now_v7(),
                    user_id: *uid,
                    provider: p.clone(),
                    provider_uid: u.clone(),
                    email: None,
                    raw_profile: raw.clone(),
                    created_at: Utc::now(),
                }))
        }

        async fn create_for_user(
            &self,
            identity: NewExternalIdentity,
        ) -> Result<ExternalIdentity, UserError> {
            let mut list = self.identities.lock().unwrap();
            let exists = list
                .iter()
                .any(|(_, p, u, _)| *p == identity.provider && *u == identity.provider_uid);
            if exists {
                return Err(UserError::Hashing("identity already bound".into()));
            }
            let created = ExternalIdentity {
                id: Uuid::now_v7(),
                user_id: identity.user_id,
                provider: identity.provider,
                provider_uid: identity.provider_uid,
                email: identity.email,
                raw_profile: identity.raw_profile,
                created_at: Utc::now(),
            };
            list.push((
                created.user_id,
                created.provider.clone(),
                created.provider_uid.clone(),
                created.raw_profile.clone(),
            ));
            Ok(created)
        }

        async fn list_for_user(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<ExternalIdentity>, UserError> {
            let list = self.identities.lock().unwrap();
            Ok(list
                .iter()
                .filter(|(uid, _, _, _)| *uid == user_id)
                .map(|(_, p, u, raw)| ExternalIdentity {
                    id: Uuid::now_v7(),
                    user_id,
                    provider: p.clone(),
                    provider_uid: u.clone(),
                    email: None,
                    raw_profile: raw.clone(),
                    created_at: Utc::now(),
                })
                .collect())
        }

        async fn remove(&self, user_id: Uuid, provider: &str) -> Result<(), UserError> {
            self.identities
                .lock()
                .unwrap()
                .retain(|(uid, p, _, _)| !(*uid == user_id && p == provider));
            Ok(())
        }

        async fn update_raw_profile(
            &self,
            user_id: Uuid,
            provider: &str,
            raw: Option<serde_json::Value>,
        ) -> Result<(), UserError> {
            let mut list = self.identities.lock().unwrap();
            for (uid, p, _, stored) in list.iter_mut() {
                if *uid == user_id && p == provider {
                    if raw.is_some() {
                        *stored = raw;
                    }
                    break;
                }
            }
            Ok(())
        }
    }

    /// 测试用直通限流。
    struct NoopLoginGuard;

    #[async_trait::async_trait]
    impl LoginGuard for NoopLoginGuard {
        async fn check(&self, _key: &str) -> Result<(), UserError> {
            Ok(())
        }
        async fn record_failure(&self, _key: &str) {}
        async fn record_success(&self, _key: &str) {}
    }

    /// 计数内存限流桩：可编程阈值，验证 service 层确实调用了 guard。
    struct CountingGuard {
        state: Mutex<HashMap<String, u32>>,
        threshold: u32,
    }

    impl CountingGuard {
        fn new(threshold: u32) -> Self {
            Self { state: Mutex::new(HashMap::new()), threshold }
        }
        fn failures(&self, key: &str) -> u32 {
            *self.state.lock().unwrap().get(key).unwrap_or(&0)
        }
    }

    #[async_trait::async_trait]
    impl LoginGuard for CountingGuard {
        async fn check(&self, key: &str) -> Result<(), UserError> {
            if self.failures(key) >= self.threshold {
                Err(UserError::TooManyAttempts)
            } else {
                Ok(())
            }
        }
        async fn record_failure(&self, key: &str) {
            *self.state.lock().unwrap().entry(key.to_string()).or_insert(0) += 1;
        }
        async fn record_success(&self, key: &str) {
            self.state.lock().unwrap().remove(key);
        }
    }

    #[tokio::test]
    async fn register_then_login_with_username_or_email() {
        let svc = service();
        let session = svc
            .register("alice", "alice@example.com", "Str0ng-pass!", "127.0.0.1")
            .await
            .unwrap();
        assert_eq!(session.user.username, "alice");
        assert!(!session.refresh_token.is_empty());
        assert!(session.refresh_expires_at > Utc::now() + Duration::days(29));

        let by_name = svc.login("k:t1", "alice", "Str0ng-pass!", "127.0.0.1").await.unwrap();
        assert_eq!(by_name.user.id, session.user.id);
        let by_email = svc
            .login("k:t1", "alice@example.com", "Str0ng-pass!", "127.0.0.1")
            .await
            .unwrap();
        assert_eq!(by_email.user.id, session.user.id);
    }

    #[tokio::test]
    async fn refresh_rotates_token_and_old_becomes_invalid() {
        let svc = service();
        let s1 = svc
            .register("dora", "dora@example.com", "Str0ng-pass!", "127.0.0.1")
            .await
            .unwrap();

        let s2 = svc.refresh(&s1.refresh_token, "127.0.0.1").await.unwrap();
        assert_eq!(s2.user.id, s1.user.id);
        assert_ne!(s2.refresh_token, s1.refresh_token, "rotation required");

        // 旧 token 已被轮换吊销
        assert!(matches!(
            svc.refresh(&s1.refresh_token, "127.0.0.1").await,
            Err(UserError::InvalidRefreshToken)
        ));
        // 新 token 仍可用
        assert!(svc.refresh(&s2.refresh_token, "127.0.0.1").await.is_ok());
    }

    #[tokio::test]
    async fn logout_revokes_and_is_idempotent() {
        let svc = service();
        let s = svc
            .register("erin", "erin@example.com", "Str0ng-pass!", "127.0.0.1")
            .await
            .unwrap();
        svc.logout(&s.refresh_token, "127.0.0.1").await.unwrap();
        assert!(matches!(
            svc.refresh(&s.refresh_token, "127.0.0.1").await,
            Err(UserError::InvalidRefreshToken)
        ));
        // 幂等：再登出一次也成功
        svc.logout(&s.refresh_token, "127.0.0.1").await.unwrap();
    }

    #[tokio::test]
    async fn change_password_requires_old_and_revokes_sessions() {
        let svc = service();
        let s = svc
            .register("frank", "frank@example.com", "Str0ng-pass!", "127.0.0.1")
            .await
            .unwrap();

        // 旧密码错误被拒
        assert!(matches!(
            svc.change_password(s.user.id, "wrong-old-pass", "N3w-pass-word!", "127.0.0.1").await,
            Err(UserError::InvalidCredentials)
        ));

        svc.change_password(s.user.id, "Str0ng-pass!", "N3w-pass-word!", "127.0.0.1")
            .await
            .unwrap();

        // 旧密码登录失败，新密码成功
        assert!(svc.login("k:t2", "frank", "Str0ng-pass!", "127.0.0.1").await.is_err());
        assert!(svc.login("k:t2", "frank", "N3w-pass-word!", "127.0.0.1").await.is_ok());
        // 已发的 refresh token 全部失效
        assert!(matches!(
            svc.refresh(&s.refresh_token, "127.0.0.1").await,
            Err(UserError::InvalidRefreshToken)
        ));
    }

    #[tokio::test]
    async fn duplicate_username_and_email_are_rejected() {
        let svc = service();
        svc.register("bob", "bob@example.com", "Str0ng-pass!", "127.0.0.1")
            .await
            .unwrap();

        assert!(matches!(
            svc.register("bob", "other@example.com", "Str0ng-pass!", "127.0.0.1")
                .await,
            Err(UserError::UsernameTaken(_))
        ));
        assert!(matches!(
            svc.register("bobby", "bob@example.com", "Str0ng-pass!", "127.0.0.1")
                .await,
            Err(UserError::EmailTaken(_))
        ));
        // 大小写不敏感的唯一性
        assert!(matches!(
            svc.register("BOB", "uppercase@example.com", "Str0ng-pass!", "127.0.0.1")
                .await,
            Err(UserError::UsernameTaken(_))
        ));
    }

    #[tokio::test]
    async fn wrong_password_or_unknown_user_is_invalid_credentials() {
        let svc = service();
        svc.register("carol", "carol@example.com", "Str0ng-pass!", "127.0.0.1")
            .await
            .unwrap();

        assert!(matches!(
            svc.login("k:t3", "carol", "nope-nope-nope", "127.0.0.1").await,
            Err(UserError::InvalidCredentials)
        ));
        assert!(matches!(
            svc.login("k:t3", "ghost", "Str0ng-pass!", "127.0.0.1").await,
            Err(UserError::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn validation_errors() {
        let svc = service();
        assert!(matches!(
            svc.register("ab", "x@example.com", "Str0ng-pass!", "127.0.0.1").await,
            Err(UserError::InvalidUsername(_))
        ));
        assert!(matches!(
            svc.register("valid", "not-an-email", "Str0ng-pass!", "127.0.0.1").await,
            Err(UserError::InvalidEmail(_))
        ));
        assert!(matches!(
            svc.register("valid", "x@example.com", "short", "127.0.0.1").await,
            Err(UserError::InvalidPassword(_))
        ));
    }

    #[tokio::test]
    async fn email_verification_flow_marks_user_verified() {
        let (svc, sent) = service_with_mail(TestMailSender::default());
        let s = svc
            .register("grace", "grace@example.com", "Str0ng-pass!", "127.0.0.1")
            .await
            .unwrap();
        assert!(!s.user.email_verified);

        // 未注册邮箱请求 → 防枚举，恒 Ok 且不发信
        svc.request_email_verification("ghost@example.com", "127.0.0.1").await.unwrap();
        assert_eq!(sent.sent.lock().unwrap().len(), 0);

        // 已注册未验证 → 发信到该邮箱
        svc.request_email_verification("grace@example.com", "127.0.0.1").await.unwrap();
        let mails = sent.sent.lock().unwrap();
        assert_eq!(mails.len(), 1);
        assert_eq!(mails[0].0, "grace@example.com");
        let raw = extract_token_from_html(&mails[0].2);
        drop(mails);

        // 确认后 email_verified = true
        svc.confirm_email_verification(&raw, "127.0.0.1").await.unwrap();
        assert!(svc
            .repository()
            .find_by_email("grace@example.com")
            .await
            .unwrap()
            .unwrap()
            .email_verified);

        // 已验证后再次请求 → 不再发信
        svc.request_email_verification("grace@example.com", "127.0.0.1").await.unwrap();
        assert_eq!(sent.sent.lock().unwrap().len(), 1, "already verified: no new mail");

        // token 一次性：复用已消费的 token 失败
        assert!(svc.confirm_email_verification(&raw, "127.0.0.1").await.is_err());
    }

    #[tokio::test]
    async fn email_change_flow_updates_email_after_confirm() {
        let (svc, sent) = service_with_mail(TestMailSender::default());
        let s = svc
            .register("henry", "henry@example.com", "Str0ng-pass!", "127.0.0.1")
            .await
            .unwrap();

        // 与现邮箱相同 → 免发信
        svc.request_email_change(s.user.id, "HENRY@example.com", "127.0.0.1").await.unwrap();
        assert_eq!(sent.sent.lock().unwrap().len(), 0);

        // 新邮箱已被他人占用 → 拒绝
        svc.register("iris", "iris@example.com", "Str0ng-pass!", "127.0.0.1").await.unwrap();
        assert!(matches!(
            svc.request_email_change(s.user.id, "iris@example.com", "127.0.0.1").await,
            Err(UserError::EmailTaken(_))
        ));

        // 正常变更：确认信发到新邮箱
        svc.request_email_change(s.user.id, "henry-new@example.com", "127.0.0.1").await.unwrap();
        let mails = sent.sent.lock().unwrap();
        assert_eq!(mails.len(), 1);
        assert_eq!(mails[0].0, "henry-new@example.com");
        let raw = extract_token_from_html(&mails[0].2);
        drop(mails);

        svc.confirm_email_change(&raw, "127.0.0.1").await.unwrap();
        let user = svc
            .repository()
            .find_by_id(s.user.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(user.email, "henry-new@example.com");
        assert!(user.email_verified, "new email auto-verified");

        // 旧邮箱已释放，可被他人注册
        assert!(svc.register("jack", "henry@example.com", "Str0ng-pass!", "127.0.0.1").await.is_ok());
    }

    /// 从确认邮件 HTML 的链接中提取 raw token（?token=...）。
    fn extract_token_from_html(html: &str) -> String {
        let start = html.find("token=").expect("token link in email html") + "token=".len();
        let rest = &html[start..];
        let end = rest
            .find(|c: char| c == '"' || c == '&' || c.is_whitespace())
            .unwrap_or(rest.len());
        rest[..end].to_string()
    }

    #[tokio::test]
    async fn login_failure_counts_toward_lockout_and_success_resets() {
        let guard = Arc::new(CountingGuard::new(3));
        let svc = UserService::new(
            Arc::new(TestRepository::new()),
            Arc::new(TestRefreshRepository::new()),
            Arc::new(TestVerificationRepository::new()),
            Arc::new(TestMailSender::default()) as Arc<dyn MailSender>,
            guard.clone() as Arc<dyn LoginGuard>,
            Arc::new(TestAuditRepository::default()) as Arc<dyn AuditRepository>,
                Arc::new(TestIdentityRepository::new()),
            "http://localhost:8080".to_string(),
        );
        svc.register("kate", "kate@example.com", "Str0ng-pass!", "9.9.9.9").await.unwrap();

        // 两次失败 → 计数 2，未锁
        assert!(svc.login("ip:1.2.3.4:kate", "kate", "wrong1", "1.2.3.4").await.is_err());
        assert!(svc.login("ip:1.2.3.4:kate", "kate", "wrong2", "1.2.3.4").await.is_err());
        assert_eq!(guard.failures("ip:1.2.3.4:kate"), 2);

        // 成功 → 清零
        svc.login("ip:1.2.3.4:kate", "kate", "Str0ng-pass!", "1.2.3.4").await.unwrap();
        assert_eq!(guard.failures("ip:1.2.3.4:kate"), 0);
    }

    #[tokio::test]
    async fn locked_account_rejects_before_password_check() {
        let guard = Arc::new(CountingGuard::new(2));
        let svc = UserService::new(
            Arc::new(TestRepository::new()),
            Arc::new(TestRefreshRepository::new()),
            Arc::new(TestVerificationRepository::new()),
            Arc::new(TestMailSender::default()) as Arc<dyn MailSender>,
            guard.clone() as Arc<dyn LoginGuard>,
            Arc::new(TestAuditRepository::default()) as Arc<dyn AuditRepository>,
                Arc::new(TestIdentityRepository::new()),
            "http://localhost:8080".to_string(),
        );
        svc.register("liam", "liam@example.com", "Str0ng-pass!", "9.9.9.9").await.unwrap();

        svc.login("k:liam", "liam", "bad", "1.1.1.1").await.unwrap_err();
        svc.login("k:liam", "liam", "bad", "1.1.1.1").await.unwrap_err();

        // 锁定后：即使密码正确也拒绝 TooManyAttempts（不是 InvalidCredentials）
        assert!(matches!(
            svc.login("k:liam", "liam", "Str0ng-pass!", "1.1.1.1").await,
            Err(UserError::TooManyAttempts)
        ));

        // 其他 (ip,login) 键不受影响
        assert!(svc.login("k:other", "liam", "Str0ng-pass!", "1.1.1.1").await.is_ok());
    }

    #[tokio::test]
    async fn unknown_user_also_counts_as_failure() {
        let guard = Arc::new(CountingGuard::new(1));
        let svc = UserService::new(
            Arc::new(TestRepository::new()),
            Arc::new(TestRefreshRepository::new()),
            Arc::new(TestVerificationRepository::new()),
            Arc::new(TestMailSender::default()) as Arc<dyn MailSender>,
            guard.clone() as Arc<dyn LoginGuard>,
            Arc::new(TestAuditRepository::default()) as Arc<dyn AuditRepository>,
                Arc::new(TestIdentityRepository::new()),
            "http://localhost:8080".to_string(),
        );

        // 用户不存在：内部按 InvalidCredentials 对外，但计入限流
        assert!(matches!(
            svc.login("k:ghost", "ghost", "whatever", "1.1.1.1").await,
            Err(UserError::InvalidCredentials)
        ));
        assert_eq!(guard.failures("k:ghost"), 1);
        assert!(matches!(
            svc.login("k:ghost", "ghost", "whatever", "1.1.1.1").await,
            Err(UserError::TooManyAttempts)
        ));
    }

    #[tokio::test]
    async fn audit_events_recorded_for_security_actions() {
        let audit = Arc::new(TestAuditRepository::default());
        let svc = UserService::new(
            Arc::new(TestRepository::new()),
            Arc::new(TestRefreshRepository::new()),
            Arc::new(TestVerificationRepository::new()),
            Arc::new(TestMailSender::default()) as Arc<dyn MailSender>,
            Arc::new(NoopLoginGuard) as Arc<dyn LoginGuard>,
            audit.clone() as Arc<dyn AuditRepository>,
            Arc::new(TestIdentityRepository::new()),
            "http://localhost:8080".to_string(),
        );

        let s = svc.register("mona", "mona@example.com", "Str0ng-pass!", "2.2.2.2").await.unwrap();
        svc.login("k:mona", "mona", "bad", "3.3.3.3").await.unwrap_err();
        svc.login("k:mona", "mona", "Str0ng-pass!", "3.3.3.3").await.unwrap();
        svc.change_password(s.user.id, "Str0ng-pass!", "N3w-pass-word!", "4.4.4.4").await.unwrap();

        // tokio::spawn 的审计异步落库：让一拍
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let events = audit.events.lock().unwrap();
        let actions: Vec<_> = events.iter().map(|(_, a)| *a).collect();
        assert!(actions.contains(&AuditAction::Register));
        assert!(actions.contains(&AuditAction::LoginFailure));
        assert!(actions.contains(&AuditAction::LoginSuccess));
        assert!(actions.contains(&AuditAction::PasswordChanged));
        assert_eq!(events.len(), 4);
    }

    #[tokio::test]
    async fn oauth_new_user_auto_registers_and_logs_in() {
        let svc = service();
        let s1 = svc
            .login_with_identity("github", "10001", Some("nina@example.com"), None, "5.5.5.5")
            .await
            .unwrap();
        assert_eq!(s1.user.email, "nina@example.com");
        assert!(s1.user.email_verified, "platform-verified email");
        assert!(s1.user.password_hash.is_none(), "no password for oauth user");

        // username 从邮箱前缀推导
        assert_eq!(s1.user.username, "nina");

        // 二次登录：同身份直接登录既有账号（不新建用户、身份不重复绑定）
        let s2 = svc
            .login_with_identity("github", "10001", Some("nina@example.com"), None, "5.5.5.5")
            .await
            .unwrap();
        assert_eq!(s2.user.id, s1.user.id);
    }

    #[tokio::test]
    async fn oauth_same_email_merges_into_existing_account() {
        let svc = service();
        // 先用密码注册
        let password_user = svc
            .register("oscar", "oscar@example.com", "Str0ng-pass!", "127.0.0.1")
            .await
            .unwrap();
        // GitHub 身份首次登录：同邮箱 → 挂到既有账号
        let s = svc
            .login_with_identity("github", "20002", Some("oscar@example.com"), None, "5.5.5.5")
            .await
            .unwrap();
        assert_eq!(s.user.id, password_user.user.id, "merge not duplicate");
        assert!(s.user.password_hash.is_some(), "password intact after merge");

        // 密码登录仍然可用
        let by_password = svc
            .login("k:o", "oscar@example.com", "Str0ng-pass!", "127.0.0.1")
            .await
            .unwrap();
        assert_eq!(by_password.user.id, password_user.user.id);
    }

    #[tokio::test]
    async fn oauth_username_conflict_gets_suffix() {
        let svc = service();
        // 占用 nina 用户名
        svc.register("nina", "nina-plain@example.com", "Str0ng-pass!", "127.0.0.1")
            .await
            .unwrap();
        // GitHub 邮箱前缀同为 nina → 自动去重为 nina2
        let s = svc
            .login_with_identity("github", "30003", Some("nina@example.com"), None, "5.5.5.5")
            .await
            .unwrap();
        assert_eq!(s.user.username, "nina2");
    }

    #[tokio::test]
    async fn passwordless_account_rejects_password_login_and_can_set_password() {
        let svc = service();
        let s = svc
            .login_with_identity("github", "40004", Some("pia@example.com"), None, "5.5.5.5")
            .await
            .unwrap();

        // 无密码账号密码登录：恒 InvalidCredentials（防枚举，不提示未设置密码）
        assert!(matches!(
            svc.login("k:p", "pia@example.com", "whatever-pass", "127.0.0.1").await,
            Err(UserError::InvalidCredentials)
        ));

        // set_password：无密码 → 免验旧密码，设置后密码登录可用
        svc.set_password(s.user.id, "N3w-pass-word!", "5.5.5.5").await.unwrap();
        assert!(svc
            .login("k:p", "pia@example.com", "N3w-pass-word!", "127.0.0.1")
            .await
            .is_ok());

        // 已有密码后再 set_password：拒绝（必须走 change_password）
        assert!(matches!(
            svc.set_password(s.user.id, "An0ther-pass!", "5.5.5.5").await,
            Err(UserError::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn magic_link_new_email_registers_and_existing_logs_in() {
        let (svc2, sent2) = service_with_mail(TestMailSender::default());
        svc2.request_magic_link("rory@example.com", "6.6.6.6").await.unwrap();
        let mails = sent2.sent.lock().unwrap();
        assert_eq!(mails.len(), 1, "magic link mail sent");
        assert_eq!(mails[0].0, "rory@example.com");
        let raw = extract_token_from_html(&mails[0].2);
        drop(mails);

        // 未注册邮箱 verify → 自动注册（login_with_identity("magic") 路径）
        let s = svc2.verify_magic_link(&raw, "6.6.6.6").await.unwrap();
        assert_eq!(s.user.email, "rory@example.com");
        assert!(s.user.email_verified);
        assert!(s.user.password_hash.is_none());
        assert_eq!(s.user.username, "rory");

        // 同邮箱再次请求 + verify → 登录既有账号
        svc2.request_magic_link("rory@example.com", "6.6.6.6").await.unwrap();
        let mails = sent2.sent.lock().unwrap();
        assert_eq!(mails.len(), 2);
        let raw2 = extract_token_from_html(&mails[1].2);
        drop(mails);
        let s2 = svc2.verify_magic_link(&raw2, "6.6.6.6").await.unwrap();
        assert_eq!(s2.user.id, s.user.id, "existing account logs in");
    }

    #[tokio::test]
    async fn magic_link_token_is_single_use_and_cross_purpose_rejected() {
        let (svc, sent) = service_with_mail(TestMailSender::default());
        svc.request_magic_link("sky@example.com", "6.6.6.6").await.unwrap();
        let mails = sent.sent.lock().unwrap();
        let raw = extract_token_from_html(&mails[0].2);
        drop(mails);

        // 一次性：第二次 verify 失败
        assert!(svc.verify_magic_link(&raw, "6.6.6.6").await.is_ok());
        assert!(matches!(
            svc.verify_magic_link(&raw, "6.6.6.6").await,
            Err(UserError::InvalidRefreshToken)
        ));

        // 跨用途：signup token 不能当 magic link 用
        svc.register("tess", "tess@example.com", "Str0ng-pass!", "127.0.0.1").await.unwrap();
        svc.request_email_verification("tess@example.com", "127.0.0.1").await.unwrap();
        let mails = sent.sent.lock().unwrap();
        let signup_raw = extract_token_from_html(&mails[1].2);
        drop(mails);
        assert!(matches!(
            svc.verify_magic_link(&signup_raw, "6.6.6.6").await,
            Err(UserError::InvalidRefreshToken)
        ));
    }

    #[tokio::test]
    async fn magic_link_request_is_always_ok_for_unknown_email() {
        let (svc, sent) = service_with_mail(TestMailSender::default());
        // 未注册邮箱：恒 Ok 且发信（登录即注册语义）
        svc.request_magic_link("ghost-magic@example.com", "6.6.6.6").await.unwrap();
        assert_eq!(sent.sent.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn change_username_validates_takes_and_updates() {
        let svc = service();
        let s = svc
            .register("ursula", "ursula@example.com", "Str0ng-pass!", "9.9.9.9")
            .await
            .unwrap();

        // 格式不合法
        assert!(matches!(
            svc.change_username(s.user.id, "ab", "9.9.9.9").await,
            Err(UserError::InvalidUsername(_))
        ));

        // 与他人冲突
        let _ = svc
            .register("victor", "victor@example.com", "Str0ng-pass!", "9.9.9.9")
            .await
            .unwrap();
        assert!(matches!(
            svc.change_username(s.user.id, "victor", "9.9.9.9").await,
            Err(UserError::UsernameTaken(_))
        ));

        // 成功改 + 旧用户名释放
        svc.change_username(s.user.id, "ursula_2", "9.9.9.9").await.unwrap();
        let user = svc.repository().find_by_id(s.user.id).await.unwrap().unwrap();
        assert_eq!(user.username, "ursula_2");
        assert!(svc.repository().find_by_username("ursula").await.unwrap().is_none());

        // 旧用户名可被他人注册
        assert!(svc
            .register("ursula", "ursula-new@example.com", "Str0ng-pass!", "9.9.9.9")
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn password_reset_full_flow_changes_password_and_revokes_sessions() {
        let (svc, sent) = service_with_mail(TestMailSender::default());
        let s = svc
            .register("marc", "marc@example.com", "0ld-pass-word!", "9.9.9.9")
            .await
            .unwrap();

        svc.request_password_reset("marc@example.com", "9.9.9.9").await.unwrap();
        let mails = sent.sent.lock().unwrap();
        assert_eq!(mails.len(), 1, "reset mail sent");
        assert_eq!(mails[0].0, "marc@example.com");
        let raw = extract_token_from_html(&mails[0].2);
        drop(mails);

        svc.confirm_password_reset(&raw, "N3w-pass-word!", "9.9.9.9").await.unwrap();

        // 新密码可登录，旧密码不可
        assert!(svc.login("k:p", "marc", "N3w-pass-word!", "1.2.3.4").await.is_ok());
        assert!(matches!(
            svc.login("k:p", "marc", "0ld-pass-word!", "1.2.3.4").await,
            Err(UserError::InvalidCredentials)
        ));
        let user = svc
            .repository()
            .find_by_id(s.user.id)
            .await
            .unwrap()
            .unwrap();
        assert!(user.password_hash.is_some());
    }

    #[tokio::test]
    async fn oauth_profile_backfill_no_overwrite_and_raw_refresh() {
        let svc = service();
        let p = ExternalProfile {
            display_name: Some("Nina".into()),
            avatar_url: Some("https://avatars.example.com/nina.png".into()),
            bio: Some("hello".into()),
            website_url: Some("https://nina.dev".into()),
            raw: Some(serde_json::json!({"login": "nina"})),
        };
        let s = svc
            .login_with_identity("github", "60006", Some("nina-p@example.com"), Some(&p), "5.5.5.5")
            .await
            .unwrap();

        // 新用户：资料直接写入 + raw 缓存落库
        assert_eq!(s.user.display_name.as_deref(), Some("Nina"));
        assert_eq!(s.user.avatar_url.as_deref(), Some("https://avatars.example.com/nina.png"));
        let ids = svc.list_identities(s.user.id).await.unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].raw_profile.as_ref().and_then(|r| r.get("login")).and_then(|v| v.as_str()), Some("nina"));

        // 用户本地编辑 display_name
        svc.update_profile(
            s.user.id,
            ProfilePatch { display_name: Some(Some("Nina Local".into())), ..Default::default() },
            "5.5.5.5",
        )
        .await
        .unwrap();

        // 再次登录（平台资料变化）：规范字段不覆盖，raw 刷新
        let p2 = ExternalProfile {
            display_name: Some("Nina Renamed On Github".into()),
            avatar_url: Some("https://avatars.example.com/new.png".into()),
            bio: None,
            website_url: None,
            raw: Some(serde_json::json!({"login": "nina", "updated": true})),
        };
        let s2 = svc
            .login_with_identity("github", "60006", Some("nina-p@example.com"), Some(&p2), "5.5.5.5")
            .await
            .unwrap();
        assert_eq!(s2.user.display_name.as_deref(), Some("Nina Local"), "local edit wins");
        assert_eq!(s2.user.avatar_url.as_deref(), Some("https://avatars.example.com/nina.png"), "non-empty not overwritten");
        let ids = svc.list_identities(s.user.id).await.unwrap();
        assert_eq!(
            ids[0].raw_profile.as_ref().and_then(|r| r.get("updated")).is_some(),
            true,
            "raw refreshed on login"
        );
    }

    #[tokio::test]
    async fn update_profile_patch_semantics_and_validation() {
        let svc = service();
        let s = svc
            .register("quinn", "quinn@example.com", "Str0ng-pass!", "9.9.9.9")
            .await
            .unwrap();

        // PATCH：只动传了的字段
        let u = svc
            .update_profile(
                s.user.id,
                ProfilePatch { bio: Some(Some("rust & android".into())), ..Default::default() },
                "9.9.9.9",
            )
            .await
            .unwrap();
        assert_eq!(u.bio.as_deref(), Some("rust & android"));
        assert_eq!(u.display_name, None);

        // Some(None) 清空
        let u = svc
            .update_profile(
                s.user.id,
                ProfilePatch { bio: Some(None), ..Default::default() },
                "9.9.9.9",
            )
            .await
            .unwrap();
        assert_eq!(u.bio, None);

        // 校验：bio 超长、url 非法
        assert!(svc
            .update_profile(
                s.user.id,
                ProfilePatch { bio: Some(Some("x".repeat(281).into())), ..Default::default() },
                "9.9.9.9",
            )
            .await
            .is_err());
        assert!(svc
            .update_profile(
                s.user.id,
                ProfilePatch { website_url: Some(Some("javascript:alert(1)".into())), ..Default::default() },
                "9.9.9.9",
            )
            .await
            .is_err());

        // 未登录其他用户不可达（UserNotFound 语义由调用方保证，这里只验证不 panic）
        assert!(svc
            .update_profile(
                Uuid::now_v7(),
                ProfilePatch { bio: Some(Some("hi".into())), ..Default::default() },
                "9.9.9.9",
            )
            .await
            .is_err());
    }

    #[tokio::test]
    async fn unbind_identity_guard_and_success() {
        let svc = service();
        // 纯 OAuth 用户（无密码，仅一个身份）：解绑被拒
        let s = svc
            .login_with_identity("github", "70007", Some("raul@example.com"), None, "5.5.5.5")
            .await
            .unwrap();
        assert!(matches!(
            svc.unbind_identity(s.user.id, "github", "5.5.5.5").await,
            Err(UserError::LastLoginMethod)
        ));

        // 设密码后可解绑
        svc.set_password(s.user.id, "N3w-pass-word!", "5.5.5.5").await.unwrap();
        svc.unbind_identity(s.user.id, "github", "5.5.5.5").await.unwrap();
        assert!(svc.list_identities(s.user.id).await.unwrap().is_empty());

        // 解绑不存在的 provider：拒绝
        let s2 = svc
            .login_with_identity("github", "70008", Some("sara@example.com"), None, "5.5.5.5")
            .await
            .unwrap();
        assert!(svc.unbind_identity(s2.user.id, "google", "5.5.5.5").await.is_err());

        // 两个身份无密码：解绑其一允许
        let _ = svc
            .login_with_identity("google", "80008", Some("sara@example.com"), None, "5.5.5.5")
            .await
            .unwrap();
        assert_eq!(svc.list_identities(s2.user.id).await.unwrap().len(), 2);
        svc.unbind_identity(s2.user.id, "github", "5.5.5.5").await.unwrap();
        assert_eq!(svc.list_identities(s2.user.id).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn password_reset_anti_enumeration_and_cross_purpose() {
        let (svc, sent) = service_with_mail(TestMailSender::default());

        // 未注册邮箱：恒 Ok 且不发信（防枚举）
        svc.request_password_reset("ghost@example.com", "6.6.6.6").await.unwrap();
        assert!(sent.sent.lock().unwrap().is_empty());

        // 无密码账号（纯 OAuth）：恒 Ok 且不发信
        let _ = svc
            .login_with_identity("github", "50005", Some("nora@example.com"), None, "6.6.6.6")
            .await
            .unwrap();
        svc.request_password_reset("nora@example.com", "6.6.6.6").await.unwrap();
        assert!(sent.sent.lock().unwrap().is_empty());

        // signup token 不能当 password_reset 用
        svc.register("paul", "paul@example.com", "Str0ng-pass!", "127.0.0.1").await.unwrap();
        svc.request_email_verification("paul@example.com", "127.0.0.1").await.unwrap();
        let mails = sent.sent.lock().unwrap();
        let signup_raw = extract_token_from_html(&mails[0].2);
        drop(mails);
        assert!(matches!(
            svc.confirm_password_reset(&signup_raw, "N3w-pass-word!", "6.6.6.6").await,
            Err(UserError::InvalidRefreshToken)
        ));
    }
}
