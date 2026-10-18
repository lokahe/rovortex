//! [`UserRepository`] 的内存实现 —— 数据库选型前的过渡实现。
//!
//! 适用：本地开发、集成测试。数据保存在进程内存中，重启即丢失；
//! 数据库落地后由 `storage_pg` 等实现替换，组合根切换即可。

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::domain::{NewUser, User, UserError};
use crate::repository::UserRepository;

#[derive(Default)]
struct Store {
    by_id: HashMap<Uuid, User>,
    username_index: HashMap<String, Uuid>,
    email_index: HashMap<String, Uuid>,
}

/// 线程安全的内存用户仓储。
#[derive(Clone, Default)]
pub struct InMemoryUserRepository {
    store: Arc<RwLock<Store>>,
}

impl InMemoryUserRepository {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl UserRepository for InMemoryUserRepository {
    async fn create(&self, new_user: NewUser) -> Result<User, UserError> {
        let mut store = self.store.write().await;

        // 统一小写比对，保证大小写不敏感的唯一性（对齐未来数据库的 lower() 唯一索引）。
        let username_key = new_user.username.to_lowercase();
        let email_key = new_user.email.to_lowercase();

        if store.username_index.contains_key(&username_key) {
            return Err(UserError::UsernameTaken(new_user.username));
        }
        if store.email_index.contains_key(&email_key) {
            return Err(UserError::EmailTaken(new_user.email));
        }

        let user = User {
            id: Uuid::now_v7(),
            username: new_user.username,
            email: new_user.email,
            password_hash: new_user.password_hash,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.username_index.insert(username_key, user.id);
        store.email_index.insert(email_key, user.id);
        store.by_id.insert(user.id, user.clone());
        Ok(user)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserError> {
        let store = self.store.read().await;
        let id = store.username_index.get(&username.to_lowercase());
        Ok(id.and_then(|id| store.by_id.get(id).cloned()))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
        let store = self.store.read().await;
        let id = store.email_index.get(&email.to_lowercase());
        Ok(id.and_then(|id| store.by_id.get(id).cloned()))
    }

    async fn find_by_login(&self, login: &str) -> Result<Option<User>, UserError> {
        let store = self.store.read().await;
        let key = login.to_lowercase();
        let id = store
            .username_index
            .get(&key)
            .or_else(|| store.email_index.get(&key));
        Ok(id.and_then(|id| store.by_id.get(id).cloned()))
    }
}
