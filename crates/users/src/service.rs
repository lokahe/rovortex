//! 用户用例编排：注册 / 登录。

use std::sync::Arc;

use crate::domain::{
    NewUser, User, UserError, validate_email, validate_password, validate_username,
};
use crate::password::{hash_password, verify_password};
use crate::repository::UserRepository;

/// 用户业务服务。持有仓储抽象，具体实现在组合根注入。
#[derive(Clone)]
pub struct UserService {
    repo: Arc<dyn UserRepository>,
}

impl UserService {
    pub fn new(repo: Arc<dyn UserRepository>) -> Self {
        Self { repo }
    }

    /// 注册：校验 → 查重 → Argon2id 哈希 → 持久化。
    pub async fn register(
        &self,
        username: &str,
        email: &str,
        password: &str,
    ) -> Result<User, UserError> {
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
        self.repo
            .create(NewUser {
                username: username.into(),
                email: email.into(),
                password_hash,
            })
            .await
    }

    /// 登录：支持用户名或邮箱。
    ///
    /// 安全设计：无论“用户不存在”还是“密码错误”，一律返回 [`UserError::InvalidCredentials`]，
    /// 避免账号枚举攻击。
    ///
    /// TODO(phase-2)：登录成功后签发 JWT 访问令牌 / 刷新令牌。
    pub async fn login(&self, login: &str, password: &str) -> Result<User, UserError> {
        let user = self
            .repo
            .find_by_login(login)
            .await?
            .ok_or(UserError::InvalidCredentials)?;

        if !verify_password(password, &user.password_hash) {
            return Err(UserError::InvalidCredentials);
        }
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::in_memory::InMemoryUserRepository;

    fn service() -> UserService {
        UserService::new(Arc::new(InMemoryUserRepository::new()))
    }

    #[tokio::test]
    async fn register_then_login_with_username_or_email() {
        let svc = service();
        let user = svc
            .register("alice", "alice@example.com", "Str0ng-pass!")
            .await
            .unwrap();
        assert_eq!(user.username, "alice");

        let by_name = svc.login("alice", "Str0ng-pass!").await.unwrap();
        assert_eq!(by_name.id, user.id);
        let by_email = svc
            .login("alice@example.com", "Str0ng-pass!")
            .await
            .unwrap();
        assert_eq!(by_email.id, user.id);
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
