//! 应用状态：依赖注入容器（组合根）。

use std::sync::Arc;

use rovortex_users::UserService;
use storage_pg::PgUserRepository;

/// 通过 `State<AppState>` 提取器在各 handler 间共享。
#[derive(Clone)]
pub struct AppState {
    pub users: Arc<UserService>,
}

impl AppState {
    /// 组装期决定具体实现。当前唯一实现：PostgreSQL。
    ///
    /// 环境变量：
    /// - `ROVORTEX_DB_URL`：Postgres DSN，默认 `postgres://localhost:5432/rovortex`
    pub async fn new() -> Self {
        let dsn = std::env::var("ROVORTEX_DB_URL").unwrap_or_else(|_| {
            "postgres://localhost:5432/rovortex".to_string()
        });

        // 迁移：启动时按序执行（编译期嵌入二进制，无需携带 SQL 文件）。
        let migrate_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&dsn)
            .await
            .expect("failed to connect to PostgreSQL for migrations");
        sqlx::migrate!("../../migrations")
            .run(&migrate_pool)
            .await
            .expect("failed to run database migrations");
        migrate_pool.close().await;

        let repo = Arc::new(
            PgUserRepository::connect(&dsn)
                .await
                .expect("failed to connect to PostgreSQL"),
        );

        Self {
            users: Arc::new(UserService::new(repo)),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        // Default 只能在同步上下文构造；正常路径走 main 里的 async new()。
        panic!("use AppState::new().await in async context")
    }
}
