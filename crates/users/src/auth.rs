//! JWT 访问令牌：签发与校验（HS256）。
//!
//! 密钥由组合根注入（`ROVORTEX_JWT_SECRET`），本模块不读取环境变量，
//! 保持业务层与配置来源解耦。claim 只带必要字段：
//! - `sub`：用户 id
//! - `exp`：过期时间
//! - `iat`：签发时间

use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::domain::UserError;

const DEFAULT_TTL_SECS: i64 = 60 * 60 * 2; // 2 小时

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iat: i64,
    exp: i64,
}

pub struct TokenSigner {
    key: EncodingKey,
    decoding_key: DecodingKey,
    ttl_secs: i64,
}

impl TokenSigner {
    pub fn new(secret: &str) -> Self {
        Self {
            key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    /// 为指定用户签发 access token。
    pub fn sign(&self, user_id: uuid::Uuid) -> Result<String, UserError> {
        let now = chrono::Utc::now().timestamp();
        let claims = Claims {
            sub: user_id.to_string(),
            iat: now,
            exp: now + self.ttl_secs,
        };
        encode(&Header::default(), &claims, &self.key)
            .map_err(|e| UserError::Hashing(format!("jwt sign: {e}")))
    }

    /// 校验 token，返回用户 id。过期 / 篡改 / 格式错误统一视为无效。
    pub fn verify(&self, token: &str) -> Result<uuid::Uuid, UserError> {
        let mut validation = Validation::default();
        validation.validate_exp = true;
        let data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|_| UserError::InvalidCredentials)?;
        data.claims
            .sub
            .parse()
            .map_err(|_| UserError::InvalidCredentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = TokenSigner::new("test-secret");
        let id = uuid::Uuid::now_v7();
        let token = signer.sign(id).unwrap();
        assert_eq!(signer.verify(&token).unwrap(), id);
    }

    #[test]
    fn wrong_secret_rejects_token() {
        let id = uuid::Uuid::now_v7();
        let token = TokenSigner::new("secret-a").sign(id).unwrap();
        assert!(TokenSigner::new("secret-b").verify(&token).is_err());
    }

    #[test]
    fn garbage_token_is_rejected() {
        let signer = TokenSigner::new("test-secret");
        assert!(signer.verify("not-a-jwt").is_err());
    }
}
