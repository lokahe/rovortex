//! 应用状态：依赖注入容器（组合根）。
//!
//! 职责：读配置 → 建立唯一一个连接池（含启动迁移）→ 组装依赖图。
//! 全项目只有这里知道具体实现（PgUserRepository / TokenSigner）。

use std::sync::Arc;

use rovortex_users::{TokenSigner, UserService};
use sqlx::PgPool;
use storage_pg::PgUserRepository;

/// 运行配置：全部来自环境变量。
struct Config {
    dsn: String,
    jwt_secret: String,
}

impl Config {
    /// 系统边界校验：缺关键配置时快速失败（fail fast）。
    fn from_env() -> Self {
        Self {
            dsn: std::env::var("ROVORTEX_DB_URL")
                .unwrap_or_else(|_| "postgres://localhost:5432/rovortex".to_string()),
            jwt_secret: std::env::var("ROVORTEX_JWT_SECRET")
                .expect("ROVORTEX_JWT_SECRET must be set"),
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

        let repo = Arc::new(PgUserRepository::from_pool(pool));
        Self {
            users: Arc::new(UserService::new(repo)),
            tokens: Arc::new(TokenSigner::new(&config.jwt_secret)),
        }
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
