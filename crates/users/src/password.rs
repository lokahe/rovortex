//! 密码哈希：Argon2id（OWASP 推荐的密码哈希算法）。
//!
//! 使用 PHC 字符串格式存储（算法、参数、盐、哈希全部内嵌），
//! 未来只需升级算法参数即可平滑迁移，无需额外的盐存储。

use argon2::Argon2;
use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};

use crate::domain::UserError;

/// 将明文密码哈希为 PHC 字符串。
pub fn hash_password(password: &str) -> Result<String, UserError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| UserError::Hashing(e.to_string()))
}

/// 校验明文密码与存储的 PHC 哈希是否匹配（常数时间比较，防时序攻击）。
pub fn verify_password(password: &str, password_hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(password_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let hash = hash_password("s3cret-Passw0rd").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("s3cret-Passw0rd", &hash));
        assert!(!verify_password("wrong-password", &hash));
    }

    #[test]
    fn salt_is_random_per_call() {
        let a = hash_password("same-input").unwrap();
        let b = hash_password("same-input").unwrap();
        assert_ne!(a, b, "same password must produce different hashes");
    }
}
