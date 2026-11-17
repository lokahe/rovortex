//! PostgreSQL 持久化实现：`rovortex-users` 的仓储契约落地版本。

pub mod audit;
pub mod email_verifications;
pub mod oauth_identities;
pub mod refresh_tokens;
pub mod repository;

pub use audit::PgAuditRepository;
pub use email_verifications::PgEmailVerificationRepository;
pub use oauth_identities::PgOauthIdentityRepository;
pub use refresh_tokens::PgRefreshTokenRepository;
pub use repository::PgUserRepository;
