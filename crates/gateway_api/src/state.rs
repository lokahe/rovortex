//! 应用状态：依赖注入容器（组合根）。
//!
//! 职责：读配置 → 建立唯一一个连接池（含启动迁移）→ 组装依赖图。
//! 全项目只有这里知道具体实现（PgUserRepository / TokenSigner / ResendSender）。

use std::sync::Arc;

use infra_mail::ResendSender;
use rovortex_users::{TokenSigner, UserService};
use sqlx::PgPool;
use storage_pg::{PgEmailVerificationRepository, PgRefreshTokenRepository, PgUserRepository};

/// 运行配置：全部来自环境变量。
struct Config {
    dsn: String,
    jwt_secret: String,
    mail_from: String,
    /// Resend API key；缺省时邮件发送退化为日志输出（本地无外部依赖开发）。
    resend_api_key: Option<String>,
    /// 验证邮件里确认链接的前缀。
    verify_url_base: String,
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
            verify_url_base: std::env::var("ROVORTEX_VERIFY_URL_BASE")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
        }
    }
}

/// 通过 `State<AppState>` 提取器在各 handler 间共享。
#[derive(Clone)]
pub struct AppState {
    pub users: Arc<UserService>,
    pub tokens: Arc<TokenSigner>,
}

impl AppState {
    pub async fn new() -> Self {
        let config = Config::from_env();
        let pool = prepare_pool(&config.dsn).await;

        let repo = Arc::new(PgUserRepository::from_pool(pool.clone()));
        let refresh_repo = Arc::new(PgRefreshTokenRepository::from_pool(pool.clone()));
        let email_verif_repo = Arc::new(PgEmailVerificationRepository::from_pool(pool));

        // 邮件发送：有 RESEND_API_KEY 用 Resend；没有则退化为日志（本地开发）。
        let mail: Arc<dyn rovortex_users::MailSender> = match &config.resend_api_key {
            Some(key) => Arc::new(ResendSender::new(key, &config.mail_from)),
            None => Arc::new(LogMailSender),
        };

        Self {
            users: Arc::new(UserService::new(
                repo,
                refresh_repo,
                email_verif_repo,
                mail,
                config.verify_url_base,
            )),
            tokens: Arc::new(TokenSigner::new(&config.jwt_secret)),
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
