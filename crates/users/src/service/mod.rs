//! 用户用例编排：注册 / 登录 / 会话刷新。

use std::sync::Arc;

use uuid::Uuid;

use crate::audit::{AuditAction, AuditRepository, NewAuditLog};
use crate::domain::{User, UserError};
use crate::email_verification::EmailVerificationRepository;
use crate::mail::MailSender;
use crate::oauth_identity::OauthIdentityRepository;
use crate::rate_limit::LoginGuard;
use crate::refresh_token::{NewRefreshToken, RefreshTokenRepository, SessionView};
use crate::repository::UserRepository;

use self::token_utils::{generate_refresh_token, hash_refresh_token};

/// users.status 的封禁值（与 admin::BANNED_STATUS 一致）。
pub const BANNED_STATUS: i16 = 1;
/// users.status 的注销值（软删，冷静期内可恢复）。
pub const DELETED_STATUS: i16 = 2;

/// 业务时序/门槛参数：由组合根从环境变量读入（gateway_api/config.rs），
/// 本 crate 只持有值 + 默认值；测试用 `with_config` 显式传值保持确定性。
#[derive(Debug, Clone)]
pub struct UserServiceConfig {
    /// refresh token 有效期（天）。
    pub refresh_ttl_days: i64,
    /// 邮箱验证/重置链接有效期（分钟）。
    pub email_verification_ttl_mins: i64,
    /// 注销冷静期（天）。到期由 cron 硬删（P7）。
    pub deletion_grace_days: i64,
    /// 密码长度上下限（字符数）。
    pub password_min_length: usize,
    pub password_max_length: usize,
    /// 验证邮件凭据通道开关：验证码 / PC 链接 / App deep link。
    pub email_channels: EmailChannels,
}

/// 邮件里渲染哪些凭据通道。全关无意义（邮件会变成空壳），
/// 组合根保证至少一项开启；二维码预留不实现。
#[derive(Debug, Clone)]
pub struct EmailChannels {
    pub code: bool,
    pub pc_link: bool,
    pub app_link: bool,
    /// App deep link scheme（如 "rovortex"）；None/空 = 不渲染 dp 段。
    pub app_link_scheme: Option<String>,
}

impl Default for EmailChannels {
    fn default() -> Self {
        // 默认：码 + PC 链接（当前线上行为）；dp 需显式配 scheme。
        Self {
            code: true,
            pc_link: true,
            app_link: false,
            app_link_scheme: None,
        }
    }
}

impl EmailChannels {
    /// deep link 可渲染 = 开关开且 scheme 非空。
    pub fn app_link_ready(&self) -> bool {
        self.app_link
            && self
                .app_link_scheme
                .as_deref()
                .is_some_and(|s| !s.is_empty())
    }

    /// 按客户端平台取通道集（email-entry 用）：
    /// - app（Android）：码 + dp，不发 PC 链接（手机点 PC 链接体验割裂）
    /// - web/pc/未知：码 + PC 链接（dp 无意义——浏览器打开深链没接管方）
    /// 开关组合仍受全局 env 约束：全局关掉的通道任何平台都不发。
    pub fn for_platform(&self, platform: &str) -> EmailChannels {
        let is_app =
            platform.eq_ignore_ascii_case("app") || platform.eq_ignore_ascii_case("android");
        if is_app {
            EmailChannels {
                code: self.code,
                pc_link: false,
                app_link: self.app_link,
                app_link_scheme: self.app_link_scheme.clone(),
            }
        } else {
            EmailChannels {
                code: self.code,
                pc_link: self.pc_link,
                app_link: false,
                app_link_scheme: None,
            }
        }
    }
}

impl Default for UserServiceConfig {
    fn default() -> Self {
        Self {
            refresh_ttl_days: 30,
            email_verification_ttl_mins: 15,
            deletion_grace_days: 30,
            password_min_length: 8,
            password_max_length: 128,
            email_channels: EmailChannels::default(),
        }
    }
}

/// 一次登录/刷新产出的完整会话：领域层不关心 JWT 细节，
/// access token 由表现层用 TokenSigner 另行签发。
#[derive(Debug, Clone)]
pub struct Session {
    pub user: User,
    /// 明文 refresh token：仅在签发瞬间存在，此后只存哈希。
    pub refresh_token: String,
    pub refresh_expires_at: chrono::DateTime<chrono::Utc>,
}

/// 会话签发时的设备上下文（表现层解析好传入）。
///
/// 隐私边界：`ua` 只存解析结果（如 "Chrome 130 · Windows"），不存原始 UA 串；
/// `ip` 只存粗粒度段（IP 前两段），完整 IP 仅进访问日志。
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    pub device_label: Option<String>,
    pub ua: Option<String>,
    pub ip: Option<String>,
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
    /// 业务时序参数（TTL / 冷静期 / 密码长度）。
    config: UserServiceConfig,
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
        Self::with_config(
            repo,
            refresh,
            email_verifications,
            mail,
            login_guard,
            audit,
            identities,
            verify_url_base,
            UserServiceConfig::default(),
        )
    }

    /// 显式配置的构造入口（测试与组合根共用）。
    #[allow(clippy::too_many_arguments)]
    pub fn with_config(
        repo: Arc<dyn UserRepository>,
        refresh: Arc<dyn RefreshTokenRepository>,
        email_verifications: Arc<dyn EmailVerificationRepository>,
        mail: Arc<dyn MailSender>,
        login_guard: Arc<dyn LoginGuard>,
        audit: Arc<dyn AuditRepository>,
        identities: Arc<dyn OauthIdentityRepository>,
        verify_url_base: String,
        config: UserServiceConfig,
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
            config,
        }
    }

    /// 暴露仓储给表现层做按 id 的资料读取（受鉴权保护，如 require_admin / users_me）。
    pub fn repository(&self) -> Arc<dyn UserRepository> {
        Arc::clone(&self.repo)
    }

    /// 密码长度校验（阈值来自 config，注册与改密码共用）。
    fn validate_password_len(&self, password: &str) -> Result<(), UserError> {
        let len = password.chars().count();
        if (self.config.password_min_length..=self.config.password_max_length).contains(&len) {
            Ok(())
        } else {
            Err(UserError::InvalidPassword(format!(
                "length must be between {} and {}",
                self.config.password_min_length, self.config.password_max_length
            )))
        }
    }

    /// 吊销用户全部会话（改密码等场景复用），返回吊销数量。
    pub async fn revoke_sessions_for(&self, user_id: Uuid) -> Result<u64, UserError> {
        self.refresh.revoke_all_for_user(user_id).await
    }

    /// 签发会话：封禁检查 → 生成 refresh token，哈希落库。
    /// 三种登录路径（密码/OAuth/Magic）共用此收口，封禁即刻生效。
    async fn issue_session(&self, user: User, ctx: &SessionContext) -> Result<Session, UserError> {
        if user.status == BANNED_STATUS {
            return Err(UserError::AccountBanned);
        }
        if user.status == DELETED_STATUS {
            return Err(UserError::AccountDeleted);
        }
        let raw = generate_refresh_token();
        let expires_at = chrono::Utc::now() + chrono::Duration::days(self.config.refresh_ttl_days);
        self.refresh
            .insert(NewRefreshToken {
                id: Uuid::now_v7(),
                user_id: user.id,
                token_hash: hash_refresh_token(&raw),
                expires_at,
                device_label: ctx.device_label.clone(),
                ua: ctx.ua.clone(),
                ip: ctx.ip.clone(),
            })
            .await?;
        Ok(Session {
            user,
            refresh_token: raw,
            refresh_expires_at: expires_at,
        })
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
}

/// 用例模块共享的令牌工具（原 service.rs 底部 helper，集中于此）。
pub(crate) mod token_utils {
    /// 生成 256 位随机 refresh token（URL 安全 Base64）。
    pub(super) fn generate_refresh_token() -> String {
        use base64::Engine as _;
        use rand_core::{OsRng, RngCore};
        let mut buf = [0u8; 32];
        OsRng.fill_bytes(&mut buf);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
    }

    /// SHA-256 哈希：明文永不落库。
    pub(super) fn hash_refresh_token(raw: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        hex_encode(&hasher.finalize())
    }

    pub(super) fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// 验证邮件凭据段的 HTML 构造（注册/重置共用；按 EmailChannels 开关拼装）。
pub(crate) mod email_creds {
    use super::EmailChannels;

    /// 验证码段（码通道开启时 Some）。
    pub(super) fn code_block(channels: &EmailChannels, code: &str) -> Option<String> {
        channels.code.then(|| format!(
            r#"  <p style="font-size:32px;letter-spacing:8px;font-weight:bold;color:#4f46e5;margin:16px 0">{code}</p>"#
        ))
    }

    /// PC 链接段（按钮 + 纯文本兜底）。
    pub(super) fn pc_link_block(
        channels: &EmailChannels,
        link: &str,
        label: &str,
    ) -> Option<String> {
        channels.pc_link.then(|| format!(
            r#"  <p style="color:#555">也可以在电脑上点击下面的链接{label}：</p>
  <p><a href="{link}" style="display:inline-block;padding:10px 20px;background:#4f46e5;color:#fff;text-decoration:none;border-radius:6px">{label}</a></p>
  <p style="color:#888;font-size:13px">如果按钮无法点击，请复制此链接到浏览器：<br><a href="{link}">{link}</a></p>"#,
            label = label,
            link = link
        ))
    }

    /// App deep link 段（开关开且 scheme 非空时 Some）。
    pub(super) fn app_link_block(
        channels: &EmailChannels,
        path: &str,
        label: &str,
    ) -> Option<String> {
        let scheme = channels.app_link_scheme.as_deref().unwrap_or("");
        channels.app_link_ready().then(|| format!(
            r#"  <p style="color:#555">在手机上点击下面的链接，直接打开应用{label}：</p>
  <p><a href="{scheme}://{path}" style="display:inline-block;padding:10px 20px;background:#0ea5e9;color:#fff;text-decoration:none;border-radius:6px">打开 App{label}</a></p>"#,
            scheme = scheme,
            path = path,
            label = label
        ))
    }

    /// 段落拼接：空行分隔，保持邮件 HTML 缩进风格。
    pub(super) fn join(parts: Vec<String>) -> String {
        parts.join("\n")
    }
}

// 按用例域拆分的 impl 块（同 crate 多 impl 合法）。
mod account;
mod email_entry;
mod email_flows;
mod login;
mod oauth;
mod password_reset;
mod registration;

#[cfg(test)]
mod tests;
