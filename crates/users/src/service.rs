//! 用户用例编排：注册 / 登录 / 会话刷新。

use std::sync::Arc;

use uuid::Uuid;

use crate::domain::{
    NewUser, User, UserError, validate_email, validate_password, validate_username,
};
use crate::password::{hash_password, verify_password};
use crate::refresh_token::{NewRefreshToken, RefreshTokenRepository};
use crate::repository::UserRepository;

const REFRESH_TTL_DAYS: i64 = 30;

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
}

impl UserService {
    pub fn new(repo: Arc<dyn UserRepository>, refresh: Arc<dyn RefreshTokenRepository>) -> Self {
        Self { repo, refresh }
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
        self.issue_session(user).await
    }

    /// 登录：支持用户名或邮箱。
    ///
    /// 安全设计：无论“用户不存在”还是“密码错误”，一律返回 [`UserError::InvalidCredentials`]，
    /// 避免账号枚举攻击。
    pub async fn login(&self, login: &str, password: &str) -> Result<Session, UserError> {
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
    pub async fn refresh(&self, raw_token: &str) -> Result<Session, UserError> {
        let token_hash = hash_refresh_token(raw_token);
        let (user_id, _) = self
            .refresh
            .find_active_by_hash(&token_hash)
            .await?
            .ok_or(UserError::InvalidRefreshToken)?;
        self.refresh.revoke_by_hash(&token_hash).await?;

        let user = self
            .repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::UserNotFound)?;
        self.issue_session(user).await
    }

    /// 登出：吊销给定 refresh token（幂等：token 无效也返回成功）。
    pub async fn logout(&self, raw_token: &str) -> Result<(), UserError> {
        self.refresh
            .revoke_by_hash(&hash_refresh_token(raw_token))
            .await
    }

    /// 修改密码：验证旧密码 → 重哈希 → 吊销该用户全部会话。
    pub async fn change_password(
        &self,
        user_id: Uuid,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), UserError> {
        validate_password(new_password)?;
        let user = self
            .repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::UserNotFound)?;
        if !verify_password(old_password, &user.password_hash) {
            return Err(UserError::InvalidCredentials);
        }
        let new_hash = hash_password(new_password)?;
        self.repo
            .update_password_hash(user_id, &new_hash)
            .await?;
        self.refresh.revoke_all_for_user(user_id).await?;
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
        UserService::new(
            Arc::new(TestRepository::new()),
            Arc::new(TestRefreshRepository::new()),
        )
    }

    #[tokio::test]
    async fn register_then_login_with_username_or_email() {
        let svc = service();
        let session = svc
            .register("alice", "alice@example.com", "Str0ng-pass!")
            .await
            .unwrap();
        assert_eq!(session.user.username, "alice");
        assert!(!session.refresh_token.is_empty());
        assert!(session.refresh_expires_at > Utc::now() + Duration::days(29));

        let by_name = svc.login("alice", "Str0ng-pass!").await.unwrap();
        assert_eq!(by_name.user.id, session.user.id);
        let by_email = svc
            .login("alice@example.com", "Str0ng-pass!")
            .await
            .unwrap();
        assert_eq!(by_email.user.id, session.user.id);
    }

    #[tokio::test]
    async fn refresh_rotates_token_and_old_becomes_invalid() {
        let svc = service();
        let s1 = svc
            .register("dora", "dora@example.com", "Str0ng-pass!")
            .await
            .unwrap();

        let s2 = svc.refresh(&s1.refresh_token).await.unwrap();
        assert_eq!(s2.user.id, s1.user.id);
        assert_ne!(s2.refresh_token, s1.refresh_token, "rotation required");

        // 旧 token 已被轮换吊销
        assert!(matches!(
            svc.refresh(&s1.refresh_token).await,
            Err(UserError::InvalidRefreshToken)
        ));
        // 新 token 仍可用
        assert!(svc.refresh(&s2.refresh_token).await.is_ok());
    }

    #[tokio::test]
    async fn logout_revokes_and_is_idempotent() {
        let svc = service();
        let s = svc
            .register("erin", "erin@example.com", "Str0ng-pass!")
            .await
            .unwrap();
        svc.logout(&s.refresh_token).await.unwrap();
        assert!(matches!(
            svc.refresh(&s.refresh_token).await,
            Err(UserError::InvalidRefreshToken)
        ));
        // 幂等：再登出一次也成功
        svc.logout(&s.refresh_token).await.unwrap();
    }

    #[tokio::test]
    async fn change_password_requires_old_and_revokes_sessions() {
        let svc = service();
        let s = svc
            .register("frank", "frank@example.com", "Str0ng-pass!")
            .await
            .unwrap();

        // 旧密码错误被拒
        assert!(matches!(
            svc.change_password(s.user.id, "wrong-old-pass", "N3w-pass-word!").await,
            Err(UserError::InvalidCredentials)
        ));

        svc.change_password(s.user.id, "Str0ng-pass!", "N3w-pass-word!")
            .await
            .unwrap();

        // 旧密码登录失败，新密码成功
        assert!(svc.login("frank", "Str0ng-pass!").await.is_err());
        assert!(svc.login("frank", "N3w-pass-word!").await.is_ok());
        // 已发的 refresh token 全部失效
        assert!(matches!(
            svc.refresh(&s.refresh_token).await,
            Err(UserError::InvalidRefreshToken)
        ));
    }

    #[tokio::test]
    async fn duplicate_username_and_email_are_rejected() {
        let svc = service();
        svc.register("bob", "bob@example.com", "Str0ng-pass!")
            .await
            .unwrap();

        assert!(matches!(
            svc.register("bob", "other@example.com", "Str0ng-pass!")
                .await,
            Err(UserError::UsernameTaken(_))
        ));
        assert!(matches!(
            svc.register("bobby", "bob@example.com", "Str0ng-pass!")
                .await,
            Err(UserError::EmailTaken(_))
        ));
        // 大小写不敏感的唯一性
        assert!(matches!(
            svc.register("BOB", "uppercase@example.com", "Str0ng-pass!")
                .await,
            Err(UserError::UsernameTaken(_))
        ));
    }

    #[tokio::test]
    async fn wrong_password_or_unknown_user_is_invalid_credentials() {
        let svc = service();
        svc.register("carol", "carol@example.com", "Str0ng-pass!")
            .await
            .unwrap();

        assert!(matches!(
            svc.login("carol", "nope-nope-nope").await,
            Err(UserError::InvalidCredentials)
        ));
        assert!(matches!(
            svc.login("ghost", "Str0ng-pass!").await,
            Err(UserError::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn validation_errors() {
        let svc = service();
        assert!(matches!(
            svc.register("ab", "x@example.com", "Str0ng-pass!").await,
            Err(UserError::InvalidUsername(_))
        ));
        assert!(matches!(
            svc.register("valid", "not-an-email", "Str0ng-pass!").await,
            Err(UserError::InvalidEmail(_))
        ));
        assert!(matches!(
            svc.register("valid", "x@example.com", "short").await,
            Err(UserError::InvalidPassword(_))
        ));
    }
}
