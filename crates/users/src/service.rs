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
use crate::password::{hash_password, verify_password};
use crate::rate_limit::LoginGuard;
use crate::refresh_token::{NewRefreshToken, RefreshTokenRepository};
use crate::repository::UserRepository;

const REFRESH_TTL_DAYS: i64 = 30;
const EMAIL_VERIFICATION_TTL_MINS: i64 = 15;

/// 一次登录/刷新产出的完整会话：领域层不关心 JWT 细节，
/// access token 由表现层用 TokenSigner 另行签发。
#[derive(Debug, Clone)]
pub struct Session {
    pub user: User,
    /// 明文 refresh token：仅在签发瞬间存在，此后只存哈希。
    pub refresh_token: String,
    pub refresh_expires_at: chrono::DateTime<chrono::Utc>,
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
        verify_url_base: String,
    ) -> Self {
        Self {
            repo,
            refresh,
            email_verifications,
            mail,
            login_guard,
            audit,
            verify_url_base,
        }
    }

    /// 暴露仓储给表现层做按 id 的资料读取（受鉴权保护）。
    pub fn repository(&self) -> Arc<dyn UserRepository> {
        Arc::clone(&self.repo)
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
                password_hash,
            })
            .await?;
        self.audit(
            Some(user.id),
            AuditAction::Register,
            format!("username={username}"),
            client_ip,
        );
        self.issue_session(user).await
    }

    /// 登录：支持用户名或邮箱。
    ///
    /// 安全设计：无论“用户不存在”还是“密码错误”，一律返回 [`UserError::InvalidCredentials`]，
    /// 避免账号枚举攻击。
    /// 写审计：失败只记日志，绝不阻断业务主流程。
    fn audit(
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
        let audit = self.audit.clone();
        tokio::spawn(async move {
            if let Err(e) = audit.append(entry).await {
                tracing::warn!(error = %e, "failed to append audit log");
            }
        });
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
                );
                self.login_guard.record_success(guard_key).await
            }
            Err(UserError::InvalidCredentials) => {
                self.audit(None, AuditAction::LoginFailure, format!("login={login}"), client_ip);
                self.login_guard.record_failure(guard_key).await
            }
            // 用户不存在也计入失败（防枚举语义下这同样是 InvalidCredentials，
            // 但防御性处理：其他错误不计入）
            Err(UserError::UserNotFound) => {
                self.audit(None, AuditAction::LoginFailure, format!("login={login}"), client_ip);
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

        if !verify_password(password, &user.password_hash) {
            return Err(UserError::InvalidCredentials);
        }
        self.issue_session(user).await
    }

    /// 用 refresh token 换取新会话（轮换：旧 token 立即吊销）。
    pub async fn refresh(&self, raw_token: &str, client_ip: &str) -> Result<Session, UserError> {
        let token_hash = hash_refresh_token(raw_token);
        let result = self.refresh_inner(&token_hash, client_ip).await;
        if result.is_err() {
            self.audit(None, AuditAction::RefreshFailure, "invalid refresh token", client_ip);
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
        self.audit(Some(user.id), AuditAction::RefreshSuccess, "", client_ip);
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
        self.audit(owner, AuditAction::Logout, "", client_ip);
        self.refresh.revoke_by_hash(&hash).await
    }

    /// 修改密码：验证旧密码 → 重哈希 → 吊销该用户全部会话。
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
        if !verify_password(old_password, &user.password_hash) {
            self.audit(Some(user_id), AuditAction::LoginFailure, "change_password: old password mismatch", client_ip);
            return Err(UserError::InvalidCredentials);
        }
        let new_hash = hash_password(new_password)?;
        self.repo
            .update_password_hash(user_id, &new_hash)
            .await?;
        self.refresh.revoke_all_for_user(user_id).await?;
        self.audit(Some(user_id), AuditAction::PasswordChanged, "", client_ip);
        Ok(())
    }

    /// 签发会话：生成 refresh token，哈希落库。
    async fn issue_session(&self, user: User) -> Result<Session, UserError> {
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
            );
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
        self.audit(Some(user.id), AuditAction::EmailVerified, format!("email={email}"), client_ip);
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
        );

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
        self.audit(Some(user_id), AuditAction::EmailChanged, format!("new={email}"), client_ip);
        self.repo.update_email(user_id, &email).await
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
            user.password_hash = new_hash.to_string();
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
                "http://localhost:8080".to_string(),
            ),
            mail,
        )
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
}
