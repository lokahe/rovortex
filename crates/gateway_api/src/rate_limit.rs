//! 登录限流的进程内实现。
//!
//! 1C1G 单实例部署够用；结构上 trait 在业务层，将来换 Redis 只改组合根。
//! 阈值/窗口由组合根注入（`config::login_guard_config`），本模块不读环境变量。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rovortex_users::{LoginGuard, UserError};

/// 登录限流参数（值对象；环境读取在 config.rs）。
pub struct LoginGuardConfig {
    pub max_failures: u32,
    pub lock_window: Duration,
}

pub struct InMemoryLoginGuard {
    max_failures: u32,
    lock_window: Duration,
    entries: Mutex<HashMap<String, Entry>>,
}

impl InMemoryLoginGuard {
    pub fn with_config(config: LoginGuardConfig) -> Self {
        Self {
            max_failures: config.max_failures,
            lock_window: config.lock_window,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// 清理过期条目（约每 256 次操作触发一次），防长期运行内存缓慢增长。
    fn maybe_gc(&self, entries: &mut HashMap<String, Entry>) {
        if entries.len() % 256 == 0 {
            let now = Instant::now();
            entries.retain(|_, e| {
                e.failures < self.max_failures
                    || self.locked_until(e).is_some_and(|t| t > now)
            });
        }
    }

    fn locked_until(&self, e: &Entry) -> Option<Instant> {
        if e.failures >= self.max_failures {
            Some(e.last_failure + self.lock_window)
        } else {
            None
        }
    }
}

impl Default for InMemoryLoginGuard {
    fn default() -> Self {
        Self::with_config(crate::config::login_guard_config())
    }
}

struct Entry {
    failures: u32,
    /// 最近一次失败时间：锁定窗口从最后一次失败起算（连续攻击持续锁住）。
    last_failure: Instant,
}

#[async_trait::async_trait]
impl LoginGuard for InMemoryLoginGuard {
    async fn check(&self, key: &str) -> Result<(), UserError> {
        let mut entries = self.entries.lock().unwrap();
        let locked = entries.get(key).and_then(|e| self.locked_until(e));
        if let Some(until) = locked {
            if until > Instant::now() {
                return Err(UserError::TooManyAttempts);
            }
            // 锁定窗口已过：这轮惩罚结束。计数视为清零重新起算，
            // 而不是"窗口外再失败 1 次立即再锁"。
            entries.remove(key);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(max: u32, window_secs: u64) -> InMemoryLoginGuard {
        InMemoryLoginGuard::with_config(LoginGuardConfig {
            max_failures: max,
            lock_window: Duration::from_secs(window_secs),
        })
    }

    #[tokio::test]
    async fn locks_after_configured_failures_and_resets_on_success() {
        let g = guard(3, 60);
        for _ in 0..3 {
            g.record_failure("k").await;
        }
        assert!(matches!(g.check("k").await, Err(UserError::TooManyAttempts)));
        // 其他 key 不受影响
        assert!(g.check("other").await.is_ok());
        // 成功后清零
        g.record_success("k").await;
        assert!(g.check("k").await.is_ok());
    }

    #[tokio::test]
    async fn below_threshold_still_allows() {
        let g = guard(9, 60);
        for _ in 0..8 {
            g.record_failure("k").await;
        }
        assert!(g.check("k").await.is_ok());
        g.record_failure("k").await;
        assert!(matches!(g.check("k").await, Err(UserError::TooManyAttempts)));
    }

    #[tokio::test]
    async fn window_expiry_unlocks() {
        let g = guard(1, 0);
        g.record_failure("k").await;
        // 窗口 0 秒：锁立即过期，check 直接放行。
        assert!(g.check("k").await.is_ok());
    }

    #[tokio::test]
    async fn positive_window_locks_then_unlocks() {
        let g = InMemoryLoginGuard::with_config(LoginGuardConfig {
            max_failures: 2,
            lock_window: Duration::from_millis(100),
        });
        g.record_failure("k").await;
        g.record_failure("k").await;
        assert!(matches!(g.check("k").await, Err(UserError::TooManyAttempts)));
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(g.check("k").await.is_ok());
        // 窗口过期后计数清零：1 次失败（< 2）不再立即锁，第 2 次才锁。
        g.record_failure("k").await;
        assert!(g.check("k").await.is_ok());
        g.record_failure("k").await;
        assert!(matches!(g.check("k").await, Err(UserError::TooManyAttempts)));
    }
}
