//! 应用状态：依赖注入容器（组合根）。

use std::sync::Arc;

use rovortex_users::{UserService, UserRepository};
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
    pub fn new() -> Self {
        let dsn = std::env::var("ROVORTEX_DB_URL").unwrap_or_else(|_| {
            "postgres://localhost:5432/rovortex".to_string()
        });
        let repo = Arc::new(
            PgUserRepository::new(&dsn)
                .expect("failed to connect to PostgreSQL"),
        );

        Self {
            users: Arc::new(UserService::new(repo)),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
