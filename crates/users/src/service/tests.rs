use super::*;
use crate::domain::NewUser;
use crate::email_verification::VerificationPurpose;
use crate::oauth_identity::{ExternalIdentity, ExternalProfile, NewExternalIdentity};
use crate::refresh_token::NewRefreshToken;
use crate::repository::UserRepository;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

#[test]
fn refresh_token_is_random_and_hashed() {
    let a = generate_refresh_token();
    let b = generate_refresh_token();
    assert_ne!(a, b);
    assert_eq!(a.len(), 43); // 32 bytes → 43 chars unpadded base64url
    assert_eq!(hash_refresh_token(&a), hash_refresh_token(&a));
    assert_ne!(hash_refresh_token(&a), hash_refresh_token(&b));
}

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

        if self
            .username_index
            .lock()
            .unwrap()
            .contains_key(&username_key)
        {
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
            deleted_at: None,
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

    async fn update_password_hash(&self, id: Uuid, new_hash: &str) -> Result<(), UserError> {
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
        self.email_index.lock().unwrap().insert(email_key, id);
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
        self.username_index.lock().unwrap().insert(username_key, id);
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

    async fn soft_delete(&self, id: Uuid) -> Result<(), UserError> {
        let mut store = self.store.lock().unwrap();
        if let Some(u) = store.get_mut(&id) {
            u.status = 2;
            u.deleted_at = Some(Utc::now());
            u.display_name = None;
            u.avatar_url = None;
            u.bio = None;
            u.website_url = None;
        }
        Ok(())
    }

    async fn restore(&self, id: Uuid) -> Result<(), UserError> {
        let mut store = self.store.lock().unwrap();
        if let Some(u) = store.get_mut(&id) {
            u.status = 0;
            u.deleted_at = None;
        }
        Ok(())
    }

    async fn set_status(&self, id: Uuid, status: i16) -> Result<(), UserError> {
        let mut store = self.store.lock().unwrap();
        let user = store.get_mut(&id).ok_or(UserError::UserNotFound)?;
        user.status = status;
        user.updated_at = Utc::now();
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

    async fn purge_deleted_before(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, UserError> {
        let mut store = self.store.lock().unwrap();
        let mut username_index = self.username_index.lock().unwrap();
        let mut email_index = self.email_index.lock().unwrap();
        let doomed: Vec<Uuid> = store
            .values()
            .filter(|u| {
                u.status == 2
                    && u.deleted_at.is_some_and(|d| d < cutoff)
            })
            .map(|u| u.id)
            .collect();
        for id in &doomed {
            store.remove(id);
            username_index.retain(|_, v| v != id);
            email_index.retain(|_, v| v != id);
        }
        Ok(doomed.len() as u64)
    }
}

/// 内存邮件桩：记录发送内容供断言。
#[derive(Default)]
struct TestMailSender {
    sent: Mutex<Vec<(String, String, String)>>, // (to, subject, html)
}

#[async_trait::async_trait]
impl MailSender for TestMailSender {
    async fn send(
        &self,
        to: &str,
        subject: &str,
        html: &str,
    ) -> Result<(), crate::mail::MailError> {
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
    tokens: Mutex<
        Vec<(
            crate::email_verification::NewEmailVerification,
            bool, // consumed
        )>,
    >,
}

impl TestVerificationRepository {
    fn new() -> Self {
        Self {
            tokens: Mutex::new(Vec::new()),
        }
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

    async fn purge_stale_before(
        &self,
        cutoff: chrono::DateTime<Utc>,
    ) -> Result<u64, UserError> {
        let mut tokens = self.tokens.lock().unwrap();
        let before = tokens.len();
        // 内存桩没有 consumed_at 时间戳：消费行按立即过期处理（end=cutoff 即可清除），
        // 未消费行与 PG 语义一致按 expires_at 判定。
        tokens.retain(|(t, consumed)| {
            let end = if *consumed { cutoff } else { t.expires_at };
            end >= cutoff
        });
        Ok((before - tokens.len()) as u64)
    }
}

/// 内存 refresh token 仓储：模拟 PG 实现的语义（哈希查找、吊销、会话列表）。
struct TestRefreshRepository {
    tokens: Mutex<HashMap<String, (Uuid, chrono::DateTime<Utc>)>>, // hash -> (user, expires)
    revoked: Mutex<std::collections::HashSet<String>>,
    sessions: Mutex<HashMap<Uuid, (Uuid, chrono::DateTime<Utc>)>>, // id -> (user, created)
}

impl TestRefreshRepository {
    fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            revoked: Mutex::new(std::collections::HashSet::new()),
            sessions: Mutex::new(HashMap::new()),
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
        self.sessions
            .lock()
            .unwrap()
            .insert(token.id, (token.user_id, Utc::now()));
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
        // 与 PG 语义一致：revoked 行不再出现在 list_active_for_user
        self.sessions
            .lock()
            .unwrap()
            .retain(|_, (uid, _)| *uid != user_id);
        Ok(n)
    }

    async fn list_active_for_user(&self, user_id: Uuid) -> Result<Vec<SessionView>, UserError> {
        let sessions = self.sessions.lock().unwrap();
        let mut out: Vec<SessionView> = sessions
            .iter()
            .filter(|(_, (uid, _))| *uid == user_id)
            .map(|(id, (_, created))| SessionView {
                id: *id,
                device_label: None,
                ua: None,
                ip: None,
                created_at: *created,
                expires_at: *created + chrono::Duration::days(30),
            })
            .collect();
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(out)
    }

    async fn revoke_by_id(&self, user_id: Uuid, id: Uuid) -> Result<bool, UserError> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.get(&id).is_some_and(|(uid, _)| *uid == user_id) {
            sessions.remove(&id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn purge_expired_before(
        &self,
        cutoff: chrono::DateTime<Utc>,
    ) -> Result<u64, UserError> {
        let mut tokens = self.tokens.lock().unwrap();
        // 与 PG 实现一致：只删过期的 token 行，不动 sessions 表。
        let before = tokens.len();
        tokens.retain(|_, (_, exp)| *exp >= cutoff);
        Ok((before - tokens.len()) as u64)
    }
}

fn service() -> UserService {
    service_with_mail(TestMailSender::default()).0
}

fn service_with_mail(mail: TestMailSender) -> (UserService, Arc<TestMailSender>) {
    service_with_channels(mail, crate::service::EmailChannels::default())
}

/// 显式传 EmailChannels 的构造（邮件通道开关测试用）。
fn service_with_channels(
    mail: TestMailSender,
    email_channels: crate::service::EmailChannels,
) -> (UserService, Arc<TestMailSender>) {
    let mail = Arc::new(mail);
    let mut config = crate::service::UserServiceConfig::default();
    config.email_channels = email_channels;
    (
        UserService::with_config(
            Arc::new(TestRepository::new()),
            Arc::new(TestRefreshRepository::new()),
            Arc::new(TestVerificationRepository::new()),
            mail.clone() as Arc<dyn MailSender>,
            Arc::new(NoopLoginGuard),
            Arc::new(TestAuditRepository::default()),
            Arc::new(TestIdentityRepository::new()),
            "http://localhost:8080".to_string(),
            config,
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
        self.events
            .lock()
            .unwrap()
            .push((entry.user_id, entry.action));
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

    async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<ExternalIdentity>, UserError> {
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
        Self {
            state: Mutex::new(HashMap::new()),
            threshold,
        }
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
        *self
            .state
            .lock()
            .unwrap()
            .entry(key.to_string())
            .or_insert(0) += 1;
    }
    async fn record_success(&self, key: &str) {
        self.state.lock().unwrap().remove(key);
    }
}

#[tokio::test]
async fn register_then_login_with_username_or_email() {
    let svc = service();
    let session = svc
        .register(
            Some("alice"),
            "alice@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(session.user.username, "alice");
    assert!(!session.refresh_token.is_empty());
    assert!(session.refresh_expires_at > Utc::now() + Duration::days(29));

    let by_name = svc
        .login(
            "k:t1",
            "alice",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(by_name.user.id, session.user.id);
    let by_email = svc
        .login(
            "k:t1",
            "alice@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(by_email.user.id, session.user.id);
}

#[tokio::test]
async fn refresh_rotates_token_and_old_becomes_invalid() {
    let svc = service();
    let s1 = svc
        .register(
            Some("dora"),
            "dora@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();

    let s2 = svc
        .refresh(&s1.refresh_token, "127.0.0.1", &SessionContext::default())
        .await
        .unwrap();
    assert_eq!(s2.user.id, s1.user.id);
    assert_ne!(s2.refresh_token, s1.refresh_token, "rotation required");

    // 旧 token 已被轮换吊销
    assert!(matches!(
        svc.refresh(&s1.refresh_token, "127.0.0.1", &SessionContext::default())
            .await,
        Err(UserError::InvalidRefreshToken)
    ));
    // 新 token 仍可用
    assert!(
        svc.refresh(&s2.refresh_token, "127.0.0.1", &SessionContext::default())
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn logout_revokes_and_is_idempotent() {
    let svc = service();
    let s = svc
        .register(
            Some("erin"),
            "erin@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    svc.logout(&s.refresh_token, "127.0.0.1").await.unwrap();
    assert!(matches!(
        svc.refresh(&s.refresh_token, "127.0.0.1", &SessionContext::default())
            .await,
        Err(UserError::InvalidRefreshToken)
    ));
    // 幂等：再登出一次也成功
    svc.logout(&s.refresh_token, "127.0.0.1").await.unwrap();
}

#[tokio::test]
async fn change_password_requires_old_and_revokes_sessions() {
    let svc = service();
    let s = svc
        .register(
            Some("frank"),
            "frank@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();

    // 旧密码错误被拒
    assert!(matches!(
        svc.change_password(s.user.id, "wrong-old-pass", "N3w-pass-word!", "127.0.0.1")
            .await,
        Err(UserError::InvalidCredentials)
    ));

    svc.change_password(s.user.id, "Str0ng-pass!", "N3w-pass-word!", "127.0.0.1")
        .await
        .unwrap();

    // 旧密码登录失败，新密码成功
    assert!(
        svc.login(
            "k:t2",
            "frank",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await
        .is_err()
    );
    assert!(
        svc.login(
            "k:t2",
            "frank",
            "N3w-pass-word!",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await
        .is_ok()
    );
    // 已发的 refresh token 全部失效
    assert!(matches!(
        svc.refresh(&s.refresh_token, "127.0.0.1", &SessionContext::default())
            .await,
        Err(UserError::InvalidRefreshToken)
    ));
}

#[tokio::test]
async fn duplicate_username_and_email_are_rejected() {
    let svc = service();
    svc.register(
        Some("bob"),
        "bob@example.com",
        "Str0ng-pass!",
        "127.0.0.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();

    assert!(matches!(
        svc.register(
            Some("bob"),
            "other@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::UsernameTaken(_))
    ));
    assert!(matches!(
        svc.register(
            None,
            "bob@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::EmailTaken(_))
    ));
    // 大小写不敏感的唯一性
    assert!(matches!(
        svc.register(
            Some("BOB"),
            "uppercase@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::UsernameTaken(_))
    ));
}

#[tokio::test]
async fn wrong_password_or_unknown_user_is_invalid_credentials() {
    let svc = service();
    svc.register(
        None,
        "carol@example.com",
        "Str0ng-pass!",
        "127.0.0.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();

    assert!(matches!(
        svc.login(
            "k:t3",
            "carol",
            "nope-nope-nope",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidCredentials)
    ));
    assert!(matches!(
        svc.login(
            "k:t3",
            "ghost",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidCredentials)
    ));
}

#[tokio::test]
async fn validation_errors() {
    let svc = service();
    assert!(matches!(
        svc.register(
            Some("ab"),
            "x@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidUsername(_))
    ));
    assert!(matches!(
        svc.register(
            None,
            "not-an-email",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidEmail(_))
    ));
    assert!(matches!(
        svc.register(
            None,
            "x@example.com",
            "short",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidPassword(_))
    ));
}

#[tokio::test]
async fn register_without_username_generates_unique_from_email() {
    let svc = service();
    let s1 = svc
        .register(
            None,
            "nina@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(s1.user.username, "nina", "generated from email prefix");
    // 同邮箱前缀再注册：自动加后缀（nina 已被占）
    let s2 = svc
        .register(
            None,
            "nina@other.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(s2.user.username, "nina2", "suffix on conflict");
}

#[tokio::test]
async fn email_verification_flow_marks_user_verified() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    let s = svc
        .register(
            Some("grace"),
            "grace@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(!s.user.email_verified);

    // 未注册邮箱请求 → 防枚举，恒 Ok 且不发信
    svc.request_email_verification("ghost@example.com", "127.0.0.1")
        .await
        .unwrap();
    assert_eq!(sent.sent.lock().unwrap().len(), 0);

    // 已注册未验证 → 发信到该邮箱
    svc.request_email_verification("grace@example.com", "127.0.0.1")
        .await
        .unwrap();
    let mails = sent.sent.lock().unwrap();
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].0, "grace@example.com");
    let raw = extract_token_from_html(&mails[0].2);
    drop(mails);

    // 确认后 email_verified = true
    svc.confirm_email_verification(&raw, "127.0.0.1")
        .await
        .unwrap();
    assert!(
        svc.repository()
            .find_by_email("grace@example.com")
            .await
            .unwrap()
            .unwrap()
            .email_verified
    );

    // 已验证后再次请求 → 不再发信
    svc.request_email_verification("grace@example.com", "127.0.0.1")
        .await
        .unwrap();
    assert_eq!(
        sent.sent.lock().unwrap().len(),
        1,
        "already verified: no new mail"
    );

    // token 一次性：复用已消费的 token 失败
    assert!(
        svc.confirm_email_verification(&raw, "127.0.0.1")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn email_change_flow_updates_email_after_confirm() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    let s = svc
        .register(
            Some("henry"),
            "henry@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();

    // 与现邮箱相同 → 免发信
    svc.request_email_change(s.user.id, "HENRY@example.com", "127.0.0.1")
        .await
        .unwrap();
    assert_eq!(sent.sent.lock().unwrap().len(), 0);

    // 新邮箱已被他人占用 → 拒绝
    svc.register(
        None,
        "iris@example.com",
        "Str0ng-pass!",
        "127.0.0.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    assert!(matches!(
        svc.request_email_change(s.user.id, "iris@example.com", "127.0.0.1")
            .await,
        Err(UserError::EmailTaken(_))
    ));

    // 正常变更：确认信发到新邮箱
    svc.request_email_change(s.user.id, "henry-new@example.com", "127.0.0.1")
        .await
        .unwrap();
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
    assert!(
        svc.register(
            None,
            "henry@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await
        .is_ok()
    );
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
    svc.register(
        None,
        "kate@example.com",
        "Str0ng-pass!",
        "9.9.9.9",
        &SessionContext::default(),
    )
    .await
    .unwrap();

    // 两次失败 → 计数 2，未锁
    assert!(
        svc.login(
            "ip:1.2.3.4:kate",
            "kate",
            "wrong1",
            "1.2.3.4",
            &SessionContext::default()
        )
        .await
        .is_err()
    );
    assert!(
        svc.login(
            "ip:1.2.3.4:kate",
            "kate",
            "wrong2",
            "1.2.3.4",
            &SessionContext::default()
        )
        .await
        .is_err()
    );
    assert_eq!(guard.failures("ip:1.2.3.4:kate"), 2);

    // 成功 → 清零
    svc.login(
        "ip:1.2.3.4:kate",
        "kate",
        "Str0ng-pass!",
        "1.2.3.4",
        &SessionContext::default(),
    )
    .await
    .unwrap();
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
    svc.register(
        None,
        "liam@example.com",
        "Str0ng-pass!",
        "9.9.9.9",
        &SessionContext::default(),
    )
    .await
    .unwrap();

    svc.login(
        "k:liam",
        "liam",
        "bad",
        "1.1.1.1",
        &SessionContext::default(),
    )
    .await
    .unwrap_err();
    svc.login(
        "k:liam",
        "liam",
        "bad",
        "1.1.1.1",
        &SessionContext::default(),
    )
    .await
    .unwrap_err();

    // 锁定后：即使密码正确也拒绝 TooManyAttempts（不是 InvalidCredentials）
    assert!(matches!(
        svc.login(
            "k:liam",
            "liam",
            "Str0ng-pass!",
            "1.1.1.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::TooManyAttempts)
    ));

    // 其他 (ip,login) 键不受影响
    assert!(
        svc.login(
            "k:other",
            "liam",
            "Str0ng-pass!",
            "1.1.1.1",
            &SessionContext::default()
        )
        .await
        .is_ok()
    );
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
        svc.login(
            "k:ghost",
            "ghost",
            "whatever",
            "1.1.1.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidCredentials)
    ));
    assert_eq!(guard.failures("k:ghost"), 1);
    assert!(matches!(
        svc.login(
            "k:ghost",
            "ghost",
            "whatever",
            "1.1.1.1",
            &SessionContext::default()
        )
        .await,
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

    let s = svc
        .register(
            None,
            "mona@example.com",
            "Str0ng-pass!",
            "2.2.2.2",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    svc.login(
        "k:mona",
        "mona",
        "bad",
        "3.3.3.3",
        &SessionContext::default(),
    )
    .await
    .unwrap_err();
    svc.login(
        "k:mona",
        "mona",
        "Str0ng-pass!",
        "3.3.3.3",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    svc.change_password(s.user.id, "Str0ng-pass!", "N3w-pass-word!", "4.4.4.4")
        .await
        .unwrap();

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
        .login_with_identity(
            "github",
            "10001",
            Some("nina@example.com"),
            None,
            "5.5.5.5",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(s1.user.email, "nina@example.com");
    assert!(s1.user.email_verified, "platform-verified email");
    assert!(
        s1.user.password_hash.is_none(),
        "no password for oauth user"
    );

    // username 从邮箱前缀推导
    assert_eq!(s1.user.username, "nina");

    // 二次登录：同身份直接登录既有账号（不新建用户、身份不重复绑定）
    let s2 = svc
        .login_with_identity(
            "github",
            "10001",
            Some("nina@example.com"),
            None,
            "5.5.5.5",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(s2.user.id, s1.user.id);
}

#[tokio::test]
async fn oauth_same_email_merges_into_existing_account() {
    let svc = service();
    // 先用密码注册
    let password_user = svc
        .register(
            Some("oscar"),
            "oscar@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    // GitHub 身份首次登录：同邮箱 → 挂到既有账号
    let s = svc
        .login_with_identity(
            "github",
            "20002",
            Some("oscar@example.com"),
            None,
            "5.5.5.5",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(s.user.id, password_user.user.id, "merge not duplicate");
    assert!(
        s.user.password_hash.is_some(),
        "password intact after merge"
    );

    // 密码登录仍然可用
    let by_password = svc
        .login(
            "k:o",
            "oscar@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(by_password.user.id, password_user.user.id);
}

#[tokio::test]
async fn oauth_username_conflict_gets_suffix() {
    let svc = service();
    // 占用 nina 用户名
    svc.register(
        Some("nina"),
        "nina-plain@example.com",
        "Str0ng-pass!",
        "127.0.0.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    // GitHub 邮箱前缀同为 nina → 自动去重为 nina2
    let s = svc
        .login_with_identity(
            "github",
            "30003",
            Some("nina@example.com"),
            None,
            "5.5.5.5",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(s.user.username, "nina2");
}

#[tokio::test]
async fn passwordless_account_rejects_password_login_and_can_set_password() {
    let svc = service();
    let s = svc
        .login_with_identity(
            "github",
            "40004",
            Some("pia@example.com"),
            None,
            "5.5.5.5",
            &SessionContext::default(),
        )
        .await
        .unwrap();

    // 无密码账号密码登录：恒 InvalidCredentials（防枚举，不提示未设置密码）
    assert!(matches!(
        svc.login(
            "k:p",
            "pia@example.com",
            "whatever-pass",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidCredentials)
    ));

    // set_password：无密码 → 免验旧密码，设置后密码登录可用
    svc.set_password(s.user.id, "N3w-pass-word!", "5.5.5.5")
        .await
        .unwrap();
    assert!(
        svc.login(
            "k:p",
            "pia@example.com",
            "N3w-pass-word!",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await
        .is_ok()
    );

    // 已有密码后再 set_password：拒绝（必须走 change_password）
    assert!(matches!(
        svc.set_password(s.user.id, "An0ther-pass!", "5.5.5.5")
            .await,
        Err(UserError::InvalidCredentials)
    ));
}

#[tokio::test]
async fn magic_link_new_email_registers_and_existing_logs_in() {
    let (svc2, sent2) = service_with_mail(TestMailSender::default());
    svc2.request_magic_link("rory@example.com", "6.6.6.6")
        .await
        .unwrap();
    let mails = sent2.sent.lock().unwrap();
    assert_eq!(mails.len(), 1, "magic link mail sent");
    assert_eq!(mails[0].0, "rory@example.com");
    let raw = extract_token_from_html(&mails[0].2);
    drop(mails);

    // 未注册邮箱 verify → 自动注册（login_with_identity("magic") 路径）
    let s = svc2
        .verify_magic_link(&raw, "6.6.6.6", &SessionContext::default())
        .await
        .unwrap();
    assert_eq!(s.user.email, "rory@example.com");
    assert!(s.user.email_verified);
    assert!(s.user.password_hash.is_none());
    assert_eq!(s.user.username, "rory");

    // 同邮箱再次请求 + verify → 登录既有账号
    svc2.request_magic_link("rory@example.com", "6.6.6.6")
        .await
        .unwrap();
    let mails = sent2.sent.lock().unwrap();
    assert_eq!(mails.len(), 2);
    let raw2 = extract_token_from_html(&mails[1].2);
    drop(mails);
    let s2 = svc2
        .verify_magic_link(&raw2, "6.6.6.6", &SessionContext::default())
        .await
        .unwrap();
    assert_eq!(s2.user.id, s.user.id, "existing account logs in");
}

#[tokio::test]
async fn magic_link_token_is_single_use_and_cross_purpose_rejected() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    svc.request_magic_link("sky@example.com", "6.6.6.6")
        .await
        .unwrap();
    let mails = sent.sent.lock().unwrap();
    let raw = extract_token_from_html(&mails[0].2);
    drop(mails);

    // 一次性：第二次 verify 失败
    assert!(
        svc.verify_magic_link(&raw, "6.6.6.6", &SessionContext::default())
            .await
            .is_ok()
    );
    assert!(matches!(
        svc.verify_magic_link(&raw, "6.6.6.6", &SessionContext::default())
            .await,
        Err(UserError::InvalidRefreshToken)
    ));

    // 跨用途：signup token 不能当 magic link 用
    svc.register(
        None,
        "tess@example.com",
        "Str0ng-pass!",
        "127.0.0.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    svc.request_email_verification("tess@example.com", "127.0.0.1")
        .await
        .unwrap();
    let mails = sent.sent.lock().unwrap();
    let signup_raw = extract_token_from_html(&mails[1].2);
    drop(mails);
    assert!(matches!(
        svc.verify_magic_link(&signup_raw, "6.6.6.6", &SessionContext::default())
            .await,
        Err(UserError::InvalidRefreshToken)
    ));
}

#[tokio::test]
async fn magic_link_request_is_always_ok_for_unknown_email() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    // 未注册邮箱：恒 Ok 且发信（登录即注册语义）
    svc.request_magic_link("ghost-magic@example.com", "6.6.6.6")
        .await
        .unwrap();
    assert_eq!(sent.sent.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn change_username_validates_takes_and_updates() {
    let svc = service();
    let s = svc
        .register(
            Some("ursula"),
            "ursula@example.com",
            "Str0ng-pass!",
            "9.9.9.9",
            &SessionContext::default(),
        )
        .await
        .unwrap();

    // 格式不合法
    assert!(matches!(
        svc.change_username(s.user.id, "ab", "9.9.9.9").await,
        Err(UserError::InvalidUsername(_))
    ));

    // 与他人冲突
    let _ = svc
        .register(
            Some("victor"),
            "victor@example.com",
            "Str0ng-pass!",
            "9.9.9.9",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(matches!(
        svc.change_username(s.user.id, "victor", "9.9.9.9").await,
        Err(UserError::UsernameTaken(_))
    ));

    // 成功改 + 旧用户名释放
    svc.change_username(s.user.id, "ursula_2", "9.9.9.9")
        .await
        .unwrap();
    let user = svc
        .repository()
        .find_by_id(s.user.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(user.username, "ursula_2");
    assert!(
        svc.repository()
            .find_by_username("ursula")
            .await
            .unwrap()
            .is_none()
    );

    // 旧用户名可被他人注册
    assert!(
        svc.register(
            Some("ursula"),
            "ursula-new@example.com",
            "Str0ng-pass!",
            "9.9.9.9",
            &SessionContext::default()
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn password_reset_full_flow_changes_password_and_revokes_sessions() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    let s = svc
        .register(
            Some("marc"),
            "marc@example.com",
            "0ld-pass-word!",
            "9.9.9.9",
            &SessionContext::default(),
        )
        .await
        .unwrap();

    // 未验证邮箱：不发信（verified 门，关接管洞）
    svc.request_password_reset("marc@example.com", "9.9.9.9")
        .await
        .unwrap();
    assert!(
        sent.sent.lock().unwrap().is_empty(),
        "unverified email gets no reset mail"
    );

    // 验证邮箱后：发码+链接，码通道改密成功
    svc.repository()
        .mark_email_verified(s.user.id)
        .await
        .unwrap();
    svc.request_password_reset("marc@example.com", "9.9.9.9")
        .await
        .unwrap();
    let mails = sent.sent.lock().unwrap();
    assert_eq!(mails.len(), 1, "reset mail sent");
    assert_eq!(mails[0].0, "marc@example.com");
    let raw = extract_token_from_html(&mails[0].2);
    drop(mails);

    svc.confirm_password_reset(&raw, "N3w-pass-word!", "9.9.9.9")
        .await
        .unwrap();

    // 新密码可登录，旧密码不可
    assert!(
        svc.login(
            "k:p",
            "marc",
            "N3w-pass-word!",
            "1.2.3.4",
            &SessionContext::default()
        )
        .await
        .is_ok()
    );
    assert!(matches!(
        svc.login(
            "k:p",
            "marc",
            "0ld-pass-word!",
            "1.2.3.4",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidCredentials)
    ));
    let user = svc
        .repository()
        .find_by_id(s.user.id)
        .await
        .unwrap()
        .unwrap();
    assert!(user.password_hash.is_some());

    // 码通道同样可用（新重置请求）
    svc.request_password_reset("marc@example.com", "9.9.9.9")
        .await
        .unwrap();
    let mails = sent.sent.lock().unwrap();
    let code2 = extract_code_from_html(&mails.last().unwrap().2);
    drop(mails);
    svc.confirm_password_reset_code("marc@example.com", &code2, "N3w-pass-word!2", "9.9.9.9")
        .await
        .unwrap();
    assert!(
        svc.login(
            "k:p",
            "marc",
            "N3w-pass-word!2",
            "1.2.3.4",
            &SessionContext::default()
        )
        .await
        .is_ok()
    );
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
        .login_with_identity(
            "github",
            "60006",
            Some("nina-p@example.com"),
            Some(&p),
            "5.5.5.5",
            &SessionContext::default(),
        )
        .await
        .unwrap();

    // 新用户：资料直接写入 + raw 缓存落库
    assert_eq!(s.user.display_name.as_deref(), Some("Nina"));
    assert_eq!(
        s.user.avatar_url.as_deref(),
        Some("https://avatars.example.com/nina.png")
    );
    let ids = svc.list_identities(s.user.id).await.unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(
        ids[0]
            .raw_profile
            .as_ref()
            .and_then(|r| r.get("login"))
            .and_then(|v| v.as_str()),
        Some("nina")
    );

    // 用户本地编辑 display_name
    svc.update_profile(
        s.user.id,
        ProfilePatch {
            display_name: Some(Some("Nina Local".into())),
            ..Default::default()
        },
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
        .login_with_identity(
            "github",
            "60006",
            Some("nina-p@example.com"),
            Some(&p2),
            "5.5.5.5",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        s2.user.display_name.as_deref(),
        Some("Nina Local"),
        "local edit wins"
    );
    assert_eq!(
        s2.user.avatar_url.as_deref(),
        Some("https://avatars.example.com/nina.png"),
        "non-empty not overwritten"
    );
    let ids = svc.list_identities(s.user.id).await.unwrap();
    assert_eq!(
        ids[0]
            .raw_profile
            .as_ref()
            .and_then(|r| r.get("updated"))
            .is_some(),
        true,
        "raw refreshed on login"
    );
}

#[tokio::test]
async fn update_profile_patch_semantics_and_validation() {
    let svc = service();
    let s = svc
        .register(
            Some("quinn"),
            "quinn@example.com",
            "Str0ng-pass!",
            "9.9.9.9",
            &SessionContext::default(),
        )
        .await
        .unwrap();

    // PATCH：只动传了的字段
    let u = svc
        .update_profile(
            s.user.id,
            ProfilePatch {
                bio: Some(Some("rust & android".into())),
                ..Default::default()
            },
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
            ProfilePatch {
                bio: Some(None),
                ..Default::default()
            },
            "9.9.9.9",
        )
        .await
        .unwrap();
    assert_eq!(u.bio, None);

    // 校验：bio 超长、url 非法
    assert!(
        svc.update_profile(
            s.user.id,
            ProfilePatch {
                bio: Some(Some("x".repeat(281).into())),
                ..Default::default()
            },
            "9.9.9.9",
        )
        .await
        .is_err()
    );
    assert!(
        svc.update_profile(
            s.user.id,
            ProfilePatch {
                website_url: Some(Some("javascript:alert(1)".into())),
                ..Default::default()
            },
            "9.9.9.9",
        )
        .await
        .is_err()
    );

    // 未登录其他用户不可达（UserNotFound 语义由调用方保证，这里只验证不 panic）
    assert!(
        svc.update_profile(
            Uuid::now_v7(),
            ProfilePatch {
                bio: Some(Some("hi".into())),
                ..Default::default()
            },
            "9.9.9.9",
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn unbind_identity_guard_and_success() {
    let svc = service();
    // 纯 OAuth 用户（无密码，仅一个身份）：解绑被拒
    let s = svc
        .login_with_identity(
            "github",
            "70007",
            Some("raul@example.com"),
            None,
            "5.5.5.5",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(matches!(
        svc.unbind_identity(s.user.id, "github", "5.5.5.5").await,
        Err(UserError::LastLoginMethod)
    ));

    // 设密码后可解绑
    svc.set_password(s.user.id, "N3w-pass-word!", "5.5.5.5")
        .await
        .unwrap();
    svc.unbind_identity(s.user.id, "github", "5.5.5.5")
        .await
        .unwrap();
    assert!(svc.list_identities(s.user.id).await.unwrap().is_empty());

    // 解绑不存在的 provider：拒绝
    let s2 = svc
        .login_with_identity(
            "github",
            "70008",
            Some("sara@example.com"),
            None,
            "5.5.5.5",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(
        svc.unbind_identity(s2.user.id, "google", "5.5.5.5")
            .await
            .is_err()
    );

    // 两个身份无密码：解绑其一允许
    let _ = svc
        .login_with_identity(
            "google",
            "80008",
            Some("sara@example.com"),
            None,
            "5.5.5.5",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(svc.list_identities(s2.user.id).await.unwrap().len(), 2);
    svc.unbind_identity(s2.user.id, "github", "5.5.5.5")
        .await
        .unwrap();
    assert_eq!(svc.list_identities(s2.user.id).await.unwrap().len(), 1);
}

#[tokio::test]
async fn sessions_list_and_revoke() {
    let svc = service();
    let s1 = svc
        .register(
            Some("fresh1"),
            "fresh1@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    // 第二次登录 = 第二个会话
    let _s2 = svc
        .login(
            "k:s2",
            "fresh1",
            "Str0ng-pass!",
            "192.168.1.7",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    let sessions = svc.list_sessions(s1.user.id).await.unwrap();
    assert_eq!(sessions.len(), 2);

    // 踢掉一个：列表减一，且该 token 失效
    let victim = sessions[0].id;
    svc.revoke_session(s1.user.id, victim, "127.0.0.1")
        .await
        .unwrap();
    assert_eq!(svc.list_sessions(s1.user.id).await.unwrap().len(), 1);

    // 踢不存在的会话 / 他人会话：UserNotFound
    assert!(matches!(
        svc.revoke_session(s1.user.id, victim, "127.0.0.1").await,
        Err(UserError::UserNotFound)
    ));

    // 越权：别的用户 id + 该会话 id 查不到
    let other = svc
        .register(
            Some("fresh2"),
            "fresh2@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(matches!(
        svc.revoke_session(other.user.id, victim, "127.0.0.1").await,
        Err(UserError::UserNotFound)
    ));
}

#[tokio::test]
async fn password_reset_anti_enumeration_and_cross_purpose() {
    let (svc, sent) = service_with_mail(TestMailSender::default());

    // 未注册邮箱：恒 Ok 且不发信（防枚举）
    svc.request_password_reset("ghost@example.com", "6.6.6.6")
        .await
        .unwrap();
    assert!(sent.sent.lock().unwrap().is_empty());

    // 无密码账号（纯 OAuth）：恒 Ok 且不发信
    let _ = svc
        .login_with_identity(
            "github",
            "50005",
            Some("nora@example.com"),
            None,
            "6.6.6.6",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    svc.request_password_reset("nora@example.com", "6.6.6.6")
        .await
        .unwrap();
    assert!(sent.sent.lock().unwrap().is_empty());

    // 未验证邮箱：恒 Ok 且不发信（verified 门）
    svc.register(
        Some("vera"),
        "vera@example.com",
        "Str0ng-pass!",
        "127.0.0.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    svc.request_password_reset("vera@example.com", "6.6.6.6")
        .await
        .unwrap();
    assert!(sent.sent.lock().unwrap().is_empty());

    // signup token 不能当 password_reset 用
    svc.register(
        None,
        "paul@example.com",
        "Str0ng-pass!",
        "127.0.0.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    svc.request_email_verification("paul@example.com", "127.0.0.1")
        .await
        .unwrap();
    let mails = sent.sent.lock().unwrap();
    let signup_raw = extract_token_from_html(&mails[0].2);
    drop(mails);
    assert!(matches!(
        svc.confirm_password_reset(&signup_raw, "N3w-pass-word!", "6.6.6.6")
            .await,
        Err(UserError::InvalidRefreshToken)
    ));
}

#[tokio::test]
async fn password_reset_code_rejects_wrong_email_and_replays() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    let s = svc
        .register(
            Some("cody"),
            "cody@example.com",
            "0ld-pass-word!",
            "9.9.9.9",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    svc.repository()
        .mark_email_verified(s.user.id)
        .await
        .unwrap();

    svc.request_password_reset("cody@example.com", "9.9.9.9")
        .await
        .unwrap();
    let mails = sent.sent.lock().unwrap();
    let code = extract_code_from_html(&mails[0].2);
    drop(mails);

    // 正确邮箱 + 正确码（大小写不敏感）：成功并吊销旧会话
    svc.confirm_password_reset_code("CODY@example.com", &code, "N3w-pass-word!", "9.9.9.9")
        .await
        .unwrap();
    assert!(
        svc.login(
            "k:p",
            "cody",
            "N3w-pass-word!",
            "1.2.3.4",
            &SessionContext::default()
        )
        .await
        .is_ok()
    );
    // 一次性：重放失败
    assert!(matches!(
        svc.confirm_password_reset_code("cody@example.com", &code, "N3w-pass-word!", "9.9.9.9")
            .await,
        Err(UserError::InvalidRefreshToken)
    ));
    // 重放也作废后：他人邮箱 + 此码同样拒绝（码绑定邮箱）
    assert!(matches!(
        svc.confirm_password_reset_code(
            "someone-else@example.com",
            &code,
            "N3w-pass-word!",
            "9.9.9.9"
        )
        .await,
        Err(UserError::InvalidRefreshToken)
    ));
}

#[tokio::test]
async fn account_deletion_soft_delete_and_recovery_flow() {
    let (svc, sent) = service_with_mail(TestMailSender::default());

    let reg = svc
        .register(
            Some("delme"),
            "delme@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    let user_id = reg.user.id;

    // 注销后：原凭据登录被拒（AccountDeleted），会话全部吊销
    svc.request_account_deletion(user_id, "127.0.0.1")
        .await
        .unwrap();
    let mails = sent.sent.lock().unwrap();
    assert_eq!(mails.len(), 1);
    let raw = extract_token_from_html(&mails[0].2);
    drop(mails);
    svc.confirm_account_deletion(&raw, "127.0.0.1")
        .await
        .unwrap();

    assert!(matches!(
        svc.login(
            "k:del",
            "delme@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::AccountDeleted)
    ));
    assert_eq!(svc.list_sessions(user_id).await.unwrap().len(), 0);

    // 冷静期内注册同邮箱：被保留占位挡住（EmailTaken）
    assert!(matches!(
        svc.register(
            None,
            "delme@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::EmailTaken(_))
    ));

    // 他人 token 不能恢复我的账号
    let other = svc
        .register(
            Some("keeper"),
            "keeper@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    svc.request_account_deletion(other.user.id, "127.0.0.1")
        .await
        .unwrap();
    let mails = sent.sent.lock().unwrap();
    let other_raw = extract_token_from_html(&mails[1].2);
    drop(mails);
    assert!(matches!(
        svc.confirm_account_recovery(&other_raw, "127.0.0.1").await,
        Err(UserError::InvalidRefreshToken)
    ));

    // 正常恢复：先请求（防枚举——未删账号不发信）
    svc.request_account_recovery("keeper@example.com", "6.6.6.6")
        .await
        .unwrap();
    assert_eq!(sent.sent.lock().unwrap().len(), 2);
    svc.request_account_recovery("delme@example.com", "6.6.6.6")
        .await
        .unwrap();
    let mails = sent.sent.lock().unwrap();
    let rec_raw = extract_token_from_html(&mails[2].2);
    drop(mails);
    svc.confirm_account_recovery(&rec_raw, "127.0.0.1")
        .await
        .unwrap();

    // 恢复后：原凭据可登录，profile 恢复
    let login = svc
        .login(
            "k:rec",
            "delme@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(login.user.id, user_id);
    assert_eq!(login.user.username, "delme");

    // 注销 token 已被吊销且一次性：再次确认失败
    assert!(matches!(
        svc.confirm_account_deletion(&raw, "127.0.0.1").await,
        Err(UserError::InvalidRefreshToken)
    ));
    // 恢复 token 同样一次性
    assert!(matches!(
        svc.confirm_account_recovery(&rec_raw, "127.0.0.1").await,
        Err(UserError::InvalidRefreshToken)
    ));
}

/// 从注册邮件 HTML 中提取 6 位验证码。
fn extract_code_from_html(html: &str) -> String {
    let marker = "margin:16px 0\">";
    let start = html.find(marker).expect("code in signup email html") + marker.len();
    html[start..start + 6].to_string()
}

#[tokio::test]
async fn signup_code_flow_creates_verified_user() {
    let (svc, sent) = service_with_mail(TestMailSender::default());

    // 已注册邮箱：防枚举，不发信
    svc.register(
        Some("tina"),
        "tina@example.com",
        "Str0ng-pass!",
        "127.0.0.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    svc.request_signup("tina@example.com", "9.9.9.9")
        .await
        .unwrap();
    assert!(sent.sent.lock().unwrap().is_empty());

    // 未注册邮箱：发信（码 + 链接双通道）
    svc.request_signup("vada@example.com", "9.9.9.9")
        .await
        .unwrap();
    let mails = sent.sent.lock().unwrap();
    assert_eq!(mails.len(), 1, "signup mail sent");
    assert_eq!(mails[0].0, "vada@example.com");
    let code = extract_code_from_html(&mails[0].2);
    let link_raw = extract_token_from_html(&mails[0].2);
    drop(mails);

    // 建号前：邮箱不存在
    assert!(
        svc.repository()
            .find_by_email("vada@example.com")
            .await
            .unwrap()
            .is_none()
    );

    // 错码：拒绝且不建号
    assert!(matches!(
        svc.confirm_signup_code(
            "vada@example.com",
            "000000",
            "Str0ng-pass!",
            None,
            "9.9.9.9",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidSignupCode)
    ));

    // 正确码 + 建号 + 直接是 verified
    let s = svc
        .confirm_signup_code(
            "vada@example.com",
            &code,
            "Str0ng-pass!",
            None,
            "9.9.9.9",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(s.user.email_verified, "signup confirm = verified");
    assert_eq!(s.user.username, "vada", "auto from email prefix");
    assert!(!s.refresh_token.is_empty());

    // 码一次性：复用失败
    assert!(matches!(
        svc.confirm_signup_code(
            "vada@example.com",
            &code,
            "Str0ng-pass!",
            None,
            "9.9.9.9",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidSignupCode)
    ));

    // 密码登录可用
    let by_password = svc
        .login(
            "k:v",
            "vada@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(by_password.user.id, s.user.id);

    // 链接通道仍可用？不——链接 token 是另一条记录，但账号已存在；
    // 链接确认会撞 EmailTaken。防御：链接确认对已存在邮箱报错。
    assert!(matches!(
        svc.confirm_signup_link(
            &link_raw,
            "An0ther-pass!",
            "9.9.9.9",
            &SessionContext::default()
        )
        .await,
        Err(UserError::EmailTaken(_))
    ));
}

#[tokio::test]
async fn signup_link_flow_creates_verified_user() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    svc.request_signup("wendy@example.com", "9.9.9.9")
        .await
        .unwrap();
    let mails = sent.sent.lock().unwrap();
    let link_raw = extract_token_from_html(&mails[0].2);
    drop(mails);

    let s = svc
        .confirm_signup_link(
            &link_raw,
            "Str0ng-pass!",
            "9.9.9.9",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(s.user.email_verified);
    assert_eq!(s.user.username, "wendy");

    // 交叉用途：signup link token 不能当 password_reset 用
    assert!(matches!(
        svc.confirm_password_reset(&link_raw, "N3w-pass-word!", "6.6.6.6")
            .await,
        Err(UserError::InvalidRefreshToken)
    ));

    // 登录可用
    assert!(
        svc.login(
            "k:w",
            "wendy@example.com",
            "Str0ng-pass!",
            "1.1.1.1",
            &SessionContext::default()
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn signup_code_rejected_for_other_email() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    svc.request_signup("xena@example.com", "9.9.9.9")
        .await
        .unwrap();
    let mails = sent.sent.lock().unwrap();
    let code = extract_code_from_html(&mails[0].2);
    drop(mails);
    // 码发给 xena，却声明是别邮箱 → 拒绝
    assert!(matches!(
        svc.confirm_signup_code(
            "yuri@example.com",
            &code,
            "Str0ng-pass!",
            None,
            "9.9.9.9",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidSignupCode)
    ));
}

#[tokio::test]
async fn signup_email_renders_all_channels_when_configured() {
    let (svc, sent) = service_with_channels(
        TestMailSender::default(),
        crate::service::EmailChannels {
            code: true,
            pc_link: true,
            app_link: true,
            app_link_scheme: Some("rovortex".into()),
        },
    );
    svc.request_signup("wanda@example.com", "9.9.9.9")
        .await
        .unwrap();
    let mails = sent.sent.lock().unwrap();
    let html = &mails[0].2;
    // 三段都在：码、PC 链接、dp（含配置的 scheme 与 signup 路径）
    assert!(html.contains("letter-spacing:8px"), "code block rendered");
    assert!(
        html.contains("http://localhost:8080/api/auth/signup/confirm?token="),
        "pc link rendered"
    );
    assert!(
        html.contains(r#"href="rovortex://signup""#),
        "deep link rendered"
    );
}

#[tokio::test]
async fn signup_email_app_link_requires_scheme() {
    // app_link=1 但 scheme 空：不渲染 dp 段（开关与 scheme 双门槛）
    let (svc, sent) = service_with_channels(
        TestMailSender::default(),
        crate::service::EmailChannels {
            code: true,
            pc_link: true,
            app_link: true,
            app_link_scheme: None,
        },
    );
    svc.request_signup("xavier@example.com", "9.9.9.9")
        .await
        .unwrap();
    let html = sent.sent.lock().unwrap()[0].2.clone();
    assert!(!html.contains("://signup"), "no deep link without scheme");
    assert!(html.contains("letter-spacing:8px"), "code still rendered");
}

#[tokio::test]
async fn signup_email_respects_channel_off_switches() {
    // 只开 dp（码/PC 关）：渲染 dp 段，无码无 PC 链接
    let (svc, sent) = service_with_channels(
        TestMailSender::default(),
        crate::service::EmailChannels {
            code: false,
            pc_link: false,
            app_link: true,
            app_link_scheme: Some("rovortex".into()),
        },
    );
    svc.request_signup("yosef@example.com", "9.9.9.9")
        .await
        .unwrap();
    let html = sent.sent.lock().unwrap()[0].2.clone();
    assert!(!html.contains("letter-spacing:8px"), "code off");
    assert!(!html.contains("/api/auth/signup/confirm"), "pc link off");
    assert!(html.contains(r#"href="rovortex://signup""#), "dp on");
}

#[tokio::test]
async fn password_reset_email_renders_deep_link_when_configured() {
    let (svc, sent) = service_with_channels(
        TestMailSender::default(),
        crate::service::EmailChannels {
            code: true,
            pc_link: true,
            app_link: true,
            app_link_scheme: Some("rovortex".into()),
        },
    );
    // 注册（legacy register 未 verified）→ 补 verified → 走重置
    svc.register(
        Some("zara"),
        "zara@example.com",
        "Str0ng-pass!",
        "127.0.0.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    let user = svc
        .repository()
        .find_by_email("zara@example.com")
        .await
        .unwrap()
        .unwrap();
    svc.repository().mark_email_verified(user.id).await.unwrap();
    svc.request_password_reset("zara@example.com", "9.9.9.9")
        .await
        .unwrap();
    let html = sent.sent.lock().unwrap()[0].2.clone();
    assert!(html.contains("letter-spacing:8px"), "reset code rendered");
    assert!(
        html.contains("rovortex://password-reset"),
        "reset dp rendered"
    );
}

// ===== email-entry 统一入口（docs/EMAIL_ENTRY.md §3）=====

/// 默认全开的通道集（entry 邮件平台矩阵测试基线）。
fn entry_channels() -> crate::service::EmailChannels {
    crate::service::EmailChannels {
        code: true,
        pc_link: true,
        app_link: true,
        app_link_scheme: Some("rovortex".into()),
    }
}

/// 场景 #1/#3：凭据对 → 会话（Some）；未注册 → None + 发码。
#[tokio::test]
async fn entry_correct_password_logs_in_unregistered_gets_code() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    svc.register(
        Some("edda"),
        "edda@example.com",
        "Str0ng-pass!",
        "127.0.0.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();

    // 密码对：直接签发会话，不发信
    let s = svc
        .request_email_entry(
            "edda@example.com",
            "Str0ng-pass!",
            "web",
            "1.1.1.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(s.is_some(), "valid credentials yield session");
    assert!(sent.sent.lock().unwrap().is_empty());

    // 未注册：None + 发码
    let s = svc
        .request_email_entry(
            "frida@example.com",
            "whatever",
            "web",
            "1.1.1.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(s.is_none());
    let mails = sent.sent.lock().unwrap();
    assert_eq!(mails.len(), 1);
    assert_eq!(mails[0].0, "frida@example.com");
    assert_eq!(mails[0].1, "Rovortex 验证码");
}

/// 场景 #4/#5：已注册 + 密码错 / 无密码 → 发码（不 401，不登录）。
#[tokio::test]
async fn entry_wrong_or_empty_password_sends_code() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    svc.register(
        Some("gina"),
        "gina@example.com",
        "Str0ng-pass!",
        "127.0.0.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();

    let s = svc
        .request_email_entry(
            "gina@example.com",
            "Wrong-pass!",
            "web",
            "1.1.1.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(s.is_none(), "wrong password: no session");
    let s = svc
        .request_email_entry(
            "gina@example.com",
            "",
            "web",
            "1.1.1.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(s.is_none(), "empty password: no session");
    assert_eq!(sent.sent.lock().unwrap().len(), 2, "both paths mailed");
}

/// 场景 #6：已注册无密码（OAuth 建号）→ 发码，码后可纯登录。
#[tokio::test]
async fn entry_oauth_account_without_password_gets_code_and_confirms_login() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    svc.login_with_identity(
        "github",
        "20001",
        Some("hana@example.com"),
        None,
        "1.1.1.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();

    let s = svc
        .request_email_entry(
            "hana@example.com",
            "",
            "web",
            "1.1.1.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(s.is_none());
    let code = {
        let mails = sent.sent.lock().unwrap();
        assert_eq!(mails.len(), 1, "no-password account mailed");
        extract_code_from_html(&mails[0].2)
    };

    // confirm 不带 password：纯登录
    let session = svc
        .confirm_email_entry(
            "hana@example.com",
            &code,
            None,
            "1.1.1.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(session.user.email, "hana@example.com");
}

/// 场景 #12/#15：已注册 + 码对 + 带 password → 静默设密并登录；不带 → 只登录。
#[tokio::test]
async fn entry_confirm_registered_sets_password_silently() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    svc.register(
        Some("iris"),
        "iris@example.com",
        "Str0ng-pass!",
        "127.0.0.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    svc.request_email_entry(
        "iris@example.com",
        "wrong",
        "web",
        "1.1.1.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    let code = {
        let m = sent.sent.lock().unwrap();
        extract_code_from_html(&m[0].2)
    };

    let session = svc
        .confirm_email_entry(
            "iris@example.com",
            &code,
            Some("N3w-pass-word!"),
            "1.1.1.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(session.user.email, "iris@example.com");
    // 新密码直接可登录（静默更新生效），旧密码失效
    let relogin = svc
        .login(
            "k:iris",
            "iris@example.com",
            "N3w-pass-word!",
            "1.1.1.1",
            &SessionContext::default(),
        )
        .await;
    assert!(relogin.is_ok(), "silent password set effective");
    assert!(
        svc.login(
            "k:iris",
            "iris@example.com",
            "Str0ng-pass!",
            "1.1.1.1",
            &SessionContext::default()
        )
        .await
        .is_err()
    );
}

/// 场景 #13：未注册 + 码对 + password → 建号（email_verified）；缺密码 → 拒绝；码一次性。
#[tokio::test]
async fn entry_confirm_unregistered_creates_account() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    svc.request_email_entry(
        "joel@example.com",
        "Str0ng-pass!",
        "web",
        "1.1.1.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();

    // 缺密码：建号必须有初始凭据。码先消费后校验（与 signup 一致），此次尝试烧掉码。
    let code0 = {
        let m = sent.sent.lock().unwrap();
        extract_code_from_html(&m[0].2)
    };
    assert!(matches!(
        svc.confirm_email_entry(
            "joel@example.com",
            &code0,
            None,
            "1.1.1.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidPassword(_))
    ));
    // 被烧掉的码重放拒绝
    assert!(matches!(
        svc.confirm_email_entry(
            "joel@example.com",
            &code0,
            Some("Str0ng-pass!"),
            "1.1.1.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidSignupCode)
    ));

    // 重新要码：带 password 建号 + verified
    svc.request_email_entry(
        "joel@example.com",
        "Str0ng-pass!",
        "web",
        "1.1.1.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    let code = {
        let m = sent.sent.lock().unwrap();
        extract_code_from_html(&m[1].2)
    };
    let session = svc
        .confirm_email_entry(
            "joel@example.com",
            &code,
            Some("Str0ng-pass!"),
            "1.1.1.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert_eq!(session.user.email, "joel@example.com");
    let user = svc
        .repository()
        .find_by_email("joel@example.com")
        .await
        .unwrap()
        .unwrap();
    assert!(user.email_verified, "entry-created account is verified");
}

/// 场景 #14：收码后、confirm 前被封禁 → 拒绝（设密与登录都不行）。
#[tokio::test]
async fn entry_confirm_rejected_if_banned_after_request() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    svc.register(
        Some("kate"),
        "kate@example.com",
        "Str0ng-pass!",
        "127.0.0.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    svc.request_email_entry(
        "kate@example.com",
        "wrong",
        "web",
        "1.1.1.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    let code = {
        let m = sent.sent.lock().unwrap();
        extract_code_from_html(&m[0].2)
    };

    let user = svc
        .repository()
        .find_by_email("kate@example.com")
        .await
        .unwrap()
        .unwrap();
    svc.repository()
        .set_status(user.id, BANNED_STATUS)
        .await
        .unwrap();
    assert!(matches!(
        svc.confirm_email_entry(
            "kate@example.com",
            &code,
            Some("Str0ng-pass!"),
            "1.1.1.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::AccountBanned)
    ));
}

/// 场景 #7：封禁/冷静期内注销账号不发信（码不能绕过封禁/恢复流程）。
#[tokio::test]
async fn entry_banned_or_deleted_account_gets_no_mail() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    let banned = svc
        .register(
            Some("lena"),
            "lena@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    svc.repository()
        .set_status(banned.user.id, BANNED_STATUS)
        .await
        .unwrap();
    let deleted = svc
        .register(
            Some("milo"),
            "milo@example.com",
            "Str0ng-pass!",
            "127.0.0.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    // 直接置冷静期软删态（request_account_deletion 只发确认邮件，软删发生在 confirm）
    svc.repository()
        .set_status(deleted.user.id, DELETED_STATUS)
        .await
        .unwrap();

    let s = svc
        .request_email_entry(
            "lena@example.com",
            "wrong",
            "web",
            "1.1.1.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(s.is_none());
    let s = svc
        .request_email_entry(
            "milo@example.com",
            "wrong",
            "web",
            "1.1.1.1",
            &SessionContext::default(),
        )
        .await
        .unwrap();
    assert!(s.is_none());
    assert!(
        sent.sent.lock().unwrap().is_empty(),
        "banned/deleted: silent, no mail"
    );
}

/// 场景 #17：entry 码不能当 signup 码用（purpose 严格比对）。
#[tokio::test]
async fn entry_code_rejected_by_signup_purpose_check() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    svc.request_email_entry(
        "nora@example.com",
        "",
        "web",
        "1.1.1.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    let code = {
        let m = sent.sent.lock().unwrap();
        extract_code_from_html(&m[0].2)
    };
    // signup confirm 消费 entry 码：purpose 不匹配 → 拒绝
    assert!(matches!(
        svc.confirm_signup_code(
            "nora@example.com",
            &code,
            "Str0ng-pass!",
            None,
            "1.1.1.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidSignupCode)
    ));
}

/// 场景 #18：码与邮箱不匹配 → 拒绝。
#[tokio::test]
async fn entry_code_rejected_for_other_email() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    svc.request_email_entry(
        "omar@example.com",
        "",
        "web",
        "1.1.1.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    let code = {
        let m = sent.sent.lock().unwrap();
        extract_code_from_html(&m[0].2)
    };
    assert!(matches!(
        svc.confirm_email_entry(
            "pia@example.com",
            &code,
            Some("Str0ng-pass!"),
            "1.1.1.1",
            &SessionContext::default()
        )
        .await,
        Err(UserError::InvalidSignupCode)
    ));
}

/// 邮箱格式非法：request 拒绝且不发信。
#[tokio::test]
async fn entry_rejects_invalid_email() {
    let (svc, sent) = service_with_mail(TestMailSender::default());
    let result = svc
        .request_email_entry(
            "not-an-email",
            "x",
            "web",
            "1.1.1.1",
            &SessionContext::default(),
        )
        .await;
    assert!(result.is_err(), "invalid email rejected");
    assert!(sent.sent.lock().unwrap().is_empty());
}

/// 密码错计入共享 login_guard（与 /api/users/login 同锁，#21）。
#[tokio::test]
async fn entry_wrong_password_counts_toward_shared_guard() {
    let guard = Arc::new(CountingGuard::new(3));
    let svc = UserService::with_config(
        Arc::new(TestRepository::new()),
        Arc::new(TestRefreshRepository::new()),
        Arc::new(TestVerificationRepository::new()),
        Arc::new(TestMailSender::default()) as Arc<dyn MailSender>,
        guard.clone() as Arc<dyn LoginGuard>,
        Arc::new(TestAuditRepository::default()),
        Arc::new(TestIdentityRepository::new()),
        "http://localhost:8080".to_string(),
        crate::service::UserServiceConfig::default(),
    );
    svc.register(
        Some("quentin"),
        "quentin@example.com",
        "Str0ng-pass!",
        "127.0.0.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();

    let key = crate::rate_limit::guard_key("9.9.9.9", "quentin@example.com");
    svc.request_email_entry(
        "quentin@example.com",
        "bad1",
        "web",
        "9.9.9.9",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    svc.request_email_entry(
        "quentin@example.com",
        "bad2",
        "web",
        "9.9.9.9",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    assert_eq!(guard.failures(&key), 2, "entry failures counted");
    // login 端点共享同一计数：再来一次错密码后达到阈值并锁 login
    svc.login(
        &key,
        "quentin@example.com",
        "bad3",
        "9.9.9.9",
        &SessionContext::default(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            svc.login(
                &key,
                "quentin@example.com",
                "Str0ng-pass!",
                "9.9.9.9",
                &SessionContext::default()
            )
            .await,
            Err(UserError::TooManyAttempts)
        ),
        "shared guard locks across both endpoints"
    );
}

/// 平台矩阵：app/android 只发码+dp（无 PC 链接）；web 只发码（无 dp）。
#[tokio::test]
async fn entry_email_platform_matrix() {
    let (svc, sent) = service_with_channels(TestMailSender::default(), entry_channels());
    // app：码 + dp
    svc.request_email_entry(
        "appuser@example.com",
        "",
        "app",
        "1.1.1.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    let html = {
        let m = sent.sent.lock().unwrap();
        m[0].2.clone()
    };
    assert!(html.contains("letter-spacing:8px"), "app: code rendered");
    assert!(
        html.contains(r#"rovortex://entry?code="#),
        "app: dp rendered"
    );
    assert!(!html.contains("/api/auth/entry"), "app: no pc link");

    // android 同 app
    svc.request_email_entry(
        "androiduser@example.com",
        "",
        "android",
        "1.1.1.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    let html = {
        let m = sent.sent.lock().unwrap();
        m[1].2.clone()
    };
    assert!(
        html.contains(r#"rovortex://entry?code="#),
        "android: dp rendered"
    );

    // web：码，无 dp（PC 链接待网页端开发时再进矩阵）
    svc.request_email_entry(
        "webuser@example.com",
        "",
        "web",
        "1.1.1.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    let html = {
        let m = sent.sent.lock().unwrap();
        m[2].2.clone()
    };
    assert!(html.contains("letter-spacing:8px"), "web: code rendered");
    assert!(!html.contains("rovortex://entry"), "web: no dp");
}

/// 全局开关仍封顶平台矩阵：全关 dp 时 app 也无 dp。
#[tokio::test]
async fn entry_email_global_switches_still_cap_platforms() {
    let (svc, sent) = service_with_channels(
        TestMailSender::default(),
        crate::service::EmailChannels {
            code: true,
            pc_link: false,
            app_link: false,
            app_link_scheme: None,
        },
    );
    svc.request_email_entry(
        "caps@example.com",
        "",
        "app",
        "1.1.1.1",
        &SessionContext::default(),
    )
    .await
    .unwrap();
    let html = sent.sent.lock().unwrap()[0].2.clone();
    assert!(html.contains("letter-spacing:8px"), "code on");
    assert!(!html.contains("rovortex://entry"), "global off caps dp");
}
