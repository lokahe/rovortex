//! 应用状态：依赖注入容器（组合根）。

use std::sync::Arc;

use rovortex_users::{InMemoryUserRepository, UserService};

/// 通过 `State<AppState>` 提取器在各 handler 间共享。
#[derive(Clone)]
pub struct AppState {
    pub users: Arc<UserService>,
}

impl AppState {
    /// 组装期决定具体实现。
    ///
    /// 当前：内存仓储（数据库选型落地前的过渡实现）。
    /// 之后：切换为 `storage_pg` 的 PostgreSQL 实现 —— 仅需修改本函数。
    pub fn new() -> Self {
        Self {
            users: Arc::new(UserService::new(Arc::new(InMemoryUserRepository::new()))),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
