//! Rovortex 用户模块 —— 核心业务层（框架无关）。
//!
//! 本 crate 刻意不依赖任何 Web 框架 / 序列化框架，只包含用户领域的业务逻辑：
//!
//! - [`domain`]：实体、值对象校验、领域错误
//! - [`password`]：密码哈希（Argon2id）
//! - [`auth`]：JWT 访问令牌（签发 / 校验）
//! - [`repository`]：仓储抽象（持久化无关的契约）
//! - [`service`]：用例编排（注册 / 登录）
//!
//! 依赖方向：`gateway_api → users`，本 crate 永远不反向依赖表现层。

pub mod admin;
pub mod audit;
pub mod auth;
pub mod db_browse;
pub mod domain;
pub mod email_verification;
pub mod mail;
pub mod oauth_identity;
pub mod password;
pub mod rate_limit;
pub mod refresh_token;
pub mod repository;
pub mod service;

pub use audit::{AuditAction, AuditEntry, AuditRepository, NewAuditLog};
pub use admin::{AdminService, AdminStats, UserDetail, UserPage};
pub use auth::TokenSigner;
pub use db_browse::{
    BrowseParams, ColumnInfo, DbBrowseError, DbBrowser, TableSummary, mask_rows,
};
pub use domain::{NewUser, User, UserError};
pub use email_verification::{
    EmailVerificationRepository, NewEmailVerification, VerificationPurpose,
};
pub use mail::{MailError, MailSender};
pub use oauth_identity::{
    ExternalIdentity, ExternalProfile, NewExternalIdentity, OauthIdentityRepository,
};
pub use rate_limit::{LoginGuard, guard_key};
pub use refresh_token::{NewRefreshToken, RefreshTokenRepository, SessionView};
pub use repository::UserRepository;
pub use service::{ProfilePatch, SessionContext, UserService};
