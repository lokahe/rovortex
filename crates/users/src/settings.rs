//! 运行期键值设置（SharedPreferences 形态）。
//!
//! 进程内 RwLock 缓存 + 写穿 PG app_settings 表：
//! - 读：纯内存，纳秒级
//! - 写：先落库再更新缓存，崩溃不丢
//! - 重启：启动时 load_all 回填缓存
//!
//! 用途：定时任务开关/频率、运营参数——改了要立即生效、重启后仍保留的状态。
//! 启动期状态（连接串、密钥）不在这里，那类在 .env / Config::from_env。

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct SettingsError(pub String);

impl std::fmt::Display for SettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "settings error: {}", self.0)
    }
}

/// 持久化仓储契约（storage_pg 实现）。
#[async_trait]
pub trait SettingsStore: Send + Sync {
    async fn load_all(&self) -> Result<HashMap<String, String>, SettingsError>;
    async fn put(&self, key: &str, value: &str) -> Result<(), SettingsError>;
}

/// 缓存层：所有读走内存，写穿。
pub struct AppSettings {
    store: Arc<dyn SettingsStore>,
    cache: RwLock<HashMap<String, String>>,
}

impl AppSettings {
    /// 启动时构造：load_all 回填缓存。
    pub async fn load(store: Arc<dyn SettingsStore>) -> Result<Self, SettingsError> {
        let all = store.load_all().await?;
        Ok(Self {
            store,
            cache: RwLock::new(all),
        })
    }

    pub async fn get(&self, key: &str) -> Option<String> {
        self.cache.read().await.get(key).cloned()
    }

    /// 布尔读取：缺省用 default；值须为 "1"/"0"，其他按 default。
    pub async fn get_bool(&self, key: &str, default: bool) -> bool {
        match self.get(key).await.as_deref() {
            Some("1") => true,
            Some("0") => false,
            _ => default,
        }
    }

    /// u64 读取：解析失败按 default。
    pub async fn get_u64(&self, key: &str, default: u64) -> u64 {
        self.get(key)
            .await
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    }

    /// 写穿：落库成功才更新缓存。失败返回错误（缓存保持旧值，与磁盘一致）。
    pub async fn set(&self, key: &str, value: &str) -> Result<(), SettingsError> {
        self.store.put(key, value).await?;
        self.cache.write().await.insert(key.to_string(), value.to_string());
        Ok(())
    }

    /// 管理页展示用：全量快照。
    pub async fn snapshot(&self) -> HashMap<String, String> {
        self.cache.read().await.clone()
    }
}
