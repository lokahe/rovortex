//! Magic Link 发信频率限制：同邮箱 1 分钟 1 条、1 小时 5 条（进程内实现）。
//!
//! 设计稿 AUTH_V2.md §5：量大再换 Redis，结构上只在本模块。

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MIN_INTERVAL: Duration = Duration::from_secs(60);
const HOURLY_LIMIT: usize = 5;
const HOURLY_WINDOW: Duration = Duration::from_secs(3600);

struct MailboxHistory {
    /// 最近发信时刻（滑窗计数用）。
    recent: VecDeque<Instant>,
}

impl MailboxHistory {
    fn new() -> Self {
        Self { recent: VecDeque::new() }
    }
}

pub struct MailRateLimiter {
    mailboxes: Mutex<std::collections::HashMap<String, MailboxHistory>>,
}

impl MailRateLimiter {
    pub fn new() -> Self {
        Self { mailboxes: Mutex::new(std::collections::HashMap::new()) }
    }

    /// 允许发信返回 Ok；超限返回 Err（附原因，HTTP 映射为 429）。
    pub fn check(&self, email: &str) -> Result<(), &'static str> {
        let now = Instant::now();
        let mut mailboxes = self.mailboxes.lock().unwrap();
        let hist = mailboxes
            .entry(email.to_lowercase())
            .or_insert_with(MailboxHistory::new);

        // 清理 1 小时窗口外的旧记录
        while hist
            .recent
            .front()
            .is_some_and(|t| now.duration_since(*t) > HOURLY_WINDOW)
        {
            hist.recent.pop_front();
        }

        if hist.recent.len() >= HOURLY_LIMIT {
            return Err("hourly limit exceeded (5/hour)");
        }
        if let Some(last) = hist.recent.back() {
            if now.duration_since(*last) < MIN_INTERVAL {
                return Err("please wait a minute before requesting again");
            }
        }

        hist.recent.push_back(now);

        // GC：条目全部过期后移除，防内存增长
        mailboxes.retain(|_, h| {
            h.recent
                .back()
                .is_some_and(|t| now.duration_since(*t) <= HOURLY_WINDOW)
        });
        Ok(())
    }
}

impl Default for MailRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_send_within_a_minute_is_rejected() {
        let limiter = MailRateLimiter::new();
        assert!(limiter.check("a@b.com").is_ok(), "first send allowed");
        let err = limiter.check("a@b.com").expect_err("second send within 60s must be rejected");
        assert!(err.contains("wait a minute"));
        // 其他邮箱不受影响
        assert!(limiter.check("other@b.com").is_ok());
    }

    #[test]
    fn hourly_limit_of_five_is_enforced() {
        let limiter = MailRateLimiter::new();
        // 不同邮箱各发一次不影响；同邮箱伪造历史直接测 5 条上限
        for _ in 0..HOURLY_LIMIT {
            // 间隔超过 1 分钟才能过 MIN_INTERVAL —— 直接操作内部状态模拟
        }
        let mut mailboxes = limiter.mailboxes.lock().unwrap();
        let hist = mailboxes.entry("x@y.com".to_string()).or_insert_with(MailboxHistory::new);
        for i in 0..HOURLY_LIMIT {
            hist.recent.push_back(Instant::now() - Duration::from_secs(120 * (i as u64 + 1)));
        }
        drop(mailboxes);
        let err = limiter.check("x@y.com").expect_err("6th send within an hour must be rejected");
        assert!(err.contains("hourly"));
    }
}
