//! 用户领域模型与领域错误。

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

/// 用户实体。
///
/// `password_hash` 为 PHC 格式的 Argon2id 串，本实体禁止对外的 serde 序列化，
/// 对外暴露一律走表现层的 DTO，防止敏感字段意外泄漏。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 创建用户所需的输入（密码已完成哈希后传入）。
#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub email: String,
    pub password_hash: String,
}

/// 领域错误 —— 表现层负责映射为 HTTP 状态码。
#[derive(Debug, Error)]
pub enum UserError {
    #[error("username `{0}` is already taken")]
    UsernameTaken(String),

    #[error("email `{0}` is already registered")]
    EmailTaken(String),

    #[error("invalid username: {0}")]
    InvalidUsername(String),

    #[error("invalid email: {0}")]
    InvalidEmail(String),

    #[error("invalid password: {0}")]
    InvalidPassword(String),

    #[error("user not found")]
    UserNotFound,

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("password hashing error: {0}")]
    Hashing(String),
}

/// 用户名规则：3-32 字符；字母开头；仅含字母 / 数字 / 下划线。
pub fn validate_username(name: &str) -> Result<(), UserError> {
    let len = name.chars().count();
    if !(3..=32).contains(&len) {
        return Err(UserError::InvalidUsername(
            "length must be between 3 and 32".into(),
        ));
    }
    let starts_ok = name.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
    let chars_ok = name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if starts_ok && chars_ok {
        Ok(())
    } else {
        Err(UserError::InvalidUsername(
            "must start with a letter and contain only letters, digits or '_'".into(),
        ))
    }
}

/// 极简邮箱校验：`local@domain.tld`。
///
/// 说明：真正的送达校验只能靠“邮箱确认信”，此处只做格式门槛；
/// 后续如需严格校验可替换为 `validator` crate 或字母箱确认流程。
pub fn validate_email(email: &str) -> Result<(), UserError> {
    let parts: Vec<&str> = email.split('@').collect();
    let ok = parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.');
    if ok {
        Ok(())
    } else {
        Err(UserError::InvalidEmail(email.into()))
    }
}

/// 密码强度门槛：8-128 字符（复杂度策略后续可在此集中扩展）。
pub fn validate_password(password: &str) -> Result<(), UserError> {
    let len = password.chars().count();
    if (8..=128).contains(&len) {
        Ok(())
    } else {
        Err(UserError::InvalidPassword(
            "length must be between 8 and 128".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_rules() {
        assert!(validate_username("alice_01").is_ok());
        assert!(validate_username("ab").is_err()); // 太短
        assert!(validate_username("1abc").is_err()); // 数字开头
        assert!(validate_username("has space").is_err()); // 非法字符
    }

    #[test]
    fn email_rules() {
        assert!(validate_email("a@b.co").is_ok());
        assert!(validate_email("no-at-sign").is_err());
        assert!(validate_email("a@nodot").is_err());
    }
}
