//! 应用状态：依赖注入容器（组合根）。
//!
//! 职责：读配置 → 建立唯一一个连接池（含启动迁移）→ 组装依赖图。
//! 全项目只有这里知道具体实现（PgUserRepository / TokenSigner / ResendSender）。

use std::sync::Arc;

use infra_mail::ResendSender;
use rovortex_users::{AdminService, DbBrowser, TokenSigner, UserService, UserServiceConfig};
use sqlx::PgPool;
use storage_pg::{PgAuditRepository, PgDbBrowser, PgEmailVerificationRepository, PgOauthIdentityRepository, PgRefreshTokenRepository, PgUserRepository};

use crate::rate_limit::InMemoryLoginGuard;

/// 运行配置：全部来自环境变量。
struct Config {
    dsn: String,
    jwt_secret: String,
    mail_from: String,
    /// Resend API key；缺省时邮件发送退化为日志输出（本地无外部依赖开发）。
    resend_api_key: Option<String>,
    /// GitHub OAuth App 凭据；两者都配置时才启用 GitHub 登录路由。
    oauth_github: Option<(String, String)>,
    /// 验证邮件里确认链接的前缀。
    verify_url_base: String,
    /// 逗号分隔的管理员邮箱名单；启动时对已有账号提升 is_admin。
    admin_emails: Vec<String>,
    /// 业务时序参数（refresh TTL / 验证链接 TTL / 注销冷静期 / 密码长度）。
    users: UserServiceConfig,
}

impl Config {
    /// 系统边界校验：缺关键配置时快速失败（fail fast）。
    fn from_env() -> Self {
        Self {
            dsn: std::env::var("ROVORTEX_DB_URL")
                .unwrap_or_else(|_| "postgres://localhost:5432/rovortex".to_string()),
            jwt_secret: std::env::var("ROVORTEX_JWT_SECRET")
                .expect("ROVORTEX_JWT_SECRET must be set"),
            mail_from: std::env::var("ROVORTEX_MAIL_FROM")
                .unwrap_or_else(|_| "onboarding@resend.dev".to_string()),
            // compose 的 ${VAR:-} 会注入空串：空 key 视同未配置，走日志降级。
            resend_api_key: std::env::var("RESEND_API_KEY")
                .ok()
                .filter(|s| !s.is_empty()),
            oauth_github: match (
                std::env::var("OAUTH_GITHUB_CLIENT_ID").ok().filter(|s| !s.is_empty()),
                std::env::var("OAUTH_GITHUB_CLIENT_SECRET").ok().filter(|s| !s.is_empty()),
            ) {
                (Some(id), Some(secret)) => Some((id, secret)),
                _ => None,
            },
            verify_url_base: std::env::var("ROVORTEX_VERIFY_URL_BASE")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            admin_emails: std::env::var("ROVORTEX_ADMIN_EMAILS")
                .map(|s| s.split(',').map(str::to_string).collect())
                .unwrap_or_default(),
            users: users_config_from_env(),
        }
    }
}

/// 业务时序参数的环境变量读取：非法/缺省一律回退默认（重启生效）。
fn users_config_from_env() -> UserServiceConfig {
    // 环境变量解析辅助：None = 未配置或非法，回退默认。
    fn env_i64(key: &str) -> Option<i64> {
        std::env::var(key).ok().and_then(|v| v.parse().ok()).filter(|n| *n > 0)
    }
    let mut cfg = UserServiceConfig::default();
    if let Some(v) = env_i64("ROVORTEX_REFRESH_TTL_DAYS") {
        cfg.refresh_ttl_days = v;
    }
    if let Some(v) = env_i64("ROVORTEX_EMAIL_VERIFICATION_TTL_MINS") {
        cfg.email_verification_ttl_mins = v;
    }
    if let Some(v) = env_i64("ROVORTEX_DELETION_GRACE_DAYS") {
        cfg.deletion_grace_days = v;
    }
    let min = env_i64("ROVORTEX_PASSWORD_MIN_LENGTH").map(|v| v as usize);
    let max = env_i64("ROVORTEX_PASSWORD_MAX_LENGTH").map(|v| v as usize);
    if let Some(min) = min {
        cfg.password_min_length = min;
    }
    if let Some(max) = max {
        cfg.password_max_length = max;
    }
    if min.is_some() && max.is_some() && cfg.password_min_length > cfg.password_max_length {
        // 上下限配置颠倒时快速失败，避免带病启动。
        panic!("ROVORTEX_PASSWORD_MIN_LENGTH must be <= ROVORTEX_PASSWORD_MAX_LENGTH");
    }
    cfg
}

/// 通过 `State<AppState>` 提取器在各 handler 间共享。
#[derive(Clone)]
pub struct AppState {
    pub users: Arc<UserService>,
    /// 管理业务（列表/详情聚合/封禁/统计/首个 admin 提升）。
    pub admin: Arc<AdminService>,
    pub tokens: Arc<TokenSigner>,
    /// 进程内 HTTP 指标（/metrics 暴露）。
    pub metrics: Arc<crate::metrics::Metrics>,
    /// 进程内日志环形缓冲（admin 日志页：历史 + SSE 实时流）。
    pub log_buffer: crate::log_buffer::LogBuffer,
    /// GitHub OAuth 凭据；None = 未配置，路由返回 404。
    pub oauth_github: Option<crate::routes::oauth::GithubOAuthConfig>,
    /// 管理端数据库浏览（只读旁路的业务层抽象，不再暴露裸连接池）。
    pub db_browser: Arc<dyn DbBrowser>,
}

impl AppState {
    /// `log_buffer` 由 main.rs 先构造（要装进 tracing subscriber）再传入，
    /// 保证 admin 日志页与 BufferLayer 写的是同一个实例。
    pub async fn with_log_buffer(log_buffer: crate::log_buffer::LogBuffer) -> Self {
        let config = Config::from_env();
        let pool = prepare_pool(&config.dsn).await;

        let repo = Arc::new(PgUserRepository::from_pool(pool.clone()));        let refresh_repo = Arc::new(PgRefreshTokenRepository::from_pool(pool.clone()));
        let email_verif_repo = Arc::new(PgEmailVerificationRepository::from_pool(pool.clone()));
        let audit_repo = Arc::new(PgAuditRepository::from_pool(pool.clone()));
        let identity_repo = Arc::new(PgOauthIdentityRepository::from_pool(pool.clone()));

        // 邮件发送：有 RESEND_API_KEY 用 Resend；没有则退化为日志（本地开发）。
        let mail: Arc<dyn rovortex_users::MailSender> = match &config.resend_api_key {
            Some(key) => Arc::new(ResendSender::new(key, &config.mail_from)),
            None => Arc::new(LogMailSender),
        };

        let users_service = Arc::new(UserService::with_config(
            repo.clone(),
            refresh_repo.clone(),
            email_verif_repo,
            mail,
            Arc::new(InMemoryLoginGuard::new()),
            audit_repo.clone(),
            identity_repo.clone(),
            config.verify_url_base,
            config.users.clone(),
        ));

        let admin_service = Arc::new(AdminService::new(
            repo,
            refresh_repo,
            audit_repo,
            identity_repo,
        ));

        // 首个 admin 的唯一入口：启动时按邮箱名单提升（幂等，账号不存在则下次启动再试）。
        if !config.admin_emails.is_empty() {
            if let Err(e) = admin_service.promote_admins(&config.admin_emails).await {
                tracing::warn!("admin promotion failed: {e}");
            }
        }

        Self {
            users: users_service,
            admin: admin_service,
            tokens: Arc::new(TokenSigner::new(&config.jwt_secret)),
            metrics: Arc::new(crate::metrics::Metrics::new()),
            log_buffer,
            oauth_github: config.oauth_github.map(|(client_id, client_secret)| {
                crate::routes::oauth::GithubOAuthConfig {
                    client_id,
                    client_secret,
                }
            }),
            db_browser: Arc::new(PgDbBrowser::from_pool(pool)),
        }
    }
}

/// 无 API key 时的降级实现：把邮件内容打到日志，方便本地开发看验证链接。
struct LogMailSender;

#[async_trait::async_trait]
impl rovortex_users::MailSender for LogMailSender {
    async fn send(&self, to: &str, subject: &str, html: &str) -> Result<(), rovortex_users::MailError> {
        tracing::warn!(to, subject, "MAIL NOT SENT (no RESEND_API_KEY); body: {}", html);
        Ok(())
    }
}

/// 建立全应用唯一的连接池，并在其上执行迁移（已执行的自动跳过）。
async fn prepare_pool(dsn: &str) -> PgPool {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(dsn)
        .await
        .expect("failed to connect to PostgreSQL");
    sqlx::migrate!("../../migrations")
        .run(&pool)
        .await
        .expect("failed to run database migrations");
    pool
}

impl Default for AppState {
    fn default() -> Self {
        // Default 只能在同步上下文构造；正常路径走 main 里的 async new()。
        panic!("use AppState::new().await in async context")
    }
}
