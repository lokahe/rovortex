//! 登录限流的进程内实现。
//!
//! 1C1G 单实例部署够用；结构上 trait 在业务层，将来换 Redis 只改组合根。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rovortex_users::{LoginGuard, UserError};

const MAX_FAILURES: u32 = 5;
const LOCK_WINDOW: Duration = Duration::from_secs(15 * 60);

struct Entry {
    failures: u32,
    /// 最近一次失败时间：锁定窗口从最后一次失败起算（连续攻击持续锁住）。
    last_failure: Instant,
}

impl Entry {
    fn locked_until(&self) -> Option<Instant> {
        if self.failures >= MAX_FAILURES {
            Some(self.last_failure + LOCK_WINDOW)
        } else {
            None
        }
    }
}

pub struct InMemoryLoginGuard {
    entries: Mutex<HashMap<String, Entry>>,
}

impl InMemoryLoginGuard {
    pub fn new() -> Self {
        Self { entries: Mutex::new(HashMap::new()) }
    }

    /// 清理过期条目（约每 256 次操作触发一次），防长期运行内存缓慢增长。
    fn maybe_gc(&self, entries: &mut HashMap<String, Entry>) {
        if entries.len() % 256 == 0 {
            let now = Instant::now();
            entries.retain(|_, e| {
                e.failures < MAX_FAILURES || e.locked_until().is_some_and(|t| t > now)
            });
        }
    }
}

impl Default for InMemoryLoginGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl LoginGuard for InMemoryLoginGuard {
    async fn check(&self, key: &str) -> Result<(), UserError> {
        let entries = self.entries.lock().unwrap();
        if let Some(e) = entries.get(key) {
            if let Some(until) = e.locked_until() {
                if until > Instant::now() {
                    return Err(UserError::TooManyAttempts);
                }
            }
        }
        Ok(())
    }

    async fn record_failure(&self, key: &str) {
        let mut entries = self.entries.lock().unwrap();
        let e = entries.entry(key.to_string()).or_insert(Entry {
            failures: 0,
            last_failure: Instant::now(),
        });
        e.failures += 1;
        e.last_failure = Instant::now();
        self.maybe_gc(&mut entries);
    }

    async fn record_success(&self, key: &str) {
        self.entries.lock().unwrap().remove(key);
    }
}
