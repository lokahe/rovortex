//! Magic Link 发信频率限制：同邮箱 1 分钟 1 条、1 小时 5 条（进程内实现）。
//!
//! 设计稿 AUTH_V2.md §5：量大再换 Redis，结构上只在本模块。
//! 间隔/上限由组合根注入（`config::mail_rate_limit_config`），本模块不读环境变量。

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 邮件限流参数（值对象；环境读取在 config.rs）。
pub struct MailRateLimitConfig {
    pub min_interval: Duration,
    pub hourly_limit: usize,
    pub hourly_window: Duration,
}

struct MailboxHistory {
    /// 最近发信时刻（滑窗计数用）。
    recent: VecDeque<Instant>,
}

impl MailboxHistory {
    fn new() -> Self {
        Self {
            recent: VecDeque::new(),
        }
    }
}

pub struct MailRateLimiter {
    min_interval: Duration,
    hourly_limit: usize,
    hourly_window: Duration,
    mailboxes: Mutex<std::collections::HashMap<String, MailboxHistory>>,
}

impl MailRateLimiter {
    pub fn with_config(config: MailRateLimitConfig) -> Self {
        Self {
            min_interval: config.min_interval,
            hourly_limit: config.hourly_limit,
            hourly_window: config.hourly_window,
            mailboxes: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// 允许发信返回 Ok；超限返回 Err（附原因，HTTP 映射为 429）。
    pub fn check(&self, email: &str) -> Result<(), &'static str> {
        let now = Instant::now();
        let mut mailboxes = self.mailboxes.lock().unwrap();
        let hist = mailboxes
            .entry(email.to_lowercase())
            .or_insert_with(MailboxHistory::new);

        // 清理滑窗外的旧记录
        while hist
            .recent
            .front()
            .is_some_and(|t| now.duration_since(*t) > self.hourly_window)
        {
            hist.recent.pop_front();
        }

        if hist.recent.len() >= self.hourly_limit {
            return Err("hourly limit exceeded");
        }
        if let Some(last) = hist.recent.back() {
            if now.duration_since(*last) < self.min_interval {
                return Err("please wait a minute before requesting again");
            }
        }

        hist.recent.push_back(now);

        // GC：条目全部过期后移除，防内存增长
        mailboxes.retain(|_, h| {
            h.recent
                .back()
                .is_some_and(|t| now.duration_since(*t) <= self.hourly_window)
        });
        Ok(())
    }
}

impl Default for MailRateLimiter {
    fn default() -> Self {
        Self::with_config(crate::config::mail_rate_limit_config())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_send_within_interval_is_rejected() {
        let limiter = MailRateLimiter::with_config(MailRateLimitConfig {
            min_interval: Duration::from_secs(60),
            hourly_limit: 5,
            hourly_window: Duration::from_secs(3600),
        });
        assert!(limiter.check("a@b.com").is_ok(), "first send allowed");
        let err = limiter
            .check("a@b.com")
            .expect_err("second send within interval must be rejected");
        assert!(err.contains("wait a minute"));
        // 其他邮箱不受影响
        assert!(limiter.check("other@b.com").is_ok());
    }

    #[test]
    fn hourly_limit_is_enforced() {
        let limiter = MailRateLimiter::with_config(MailRateLimitConfig {
            min_interval: Duration::from_secs(1),
            hourly_limit: 5,
            hourly_window: Duration::from_secs(3600),
        });
        // 同邮箱伪造历史直接测上限
        let mut mailboxes = limiter.mailboxes.lock().unwrap();
        let hist = mailboxes
            .entry("x@y.com".to_string())
            .or_insert_with(MailboxHistory::new);
        for i in 0..5 {
            hist.recent
                .push_back(Instant::now() - Duration::from_secs(120 * (i as u64 + 1)));
        }
        drop(mailboxes);
        let err = limiter
            .check("x@y.com")
            .expect_err("6th send within window must be rejected");
        assert!(err.contains("hourly"));
    }

    #[test]
    fn custom_config_changes_behavior() {
        // 间隔 0 秒：连发多条都允许，直到小时上限
        let limiter = MailRateLimiter::with_config(MailRateLimitConfig {
            min_interval: Duration::from_secs(0),
            hourly_limit: 2,
            hourly_window: Duration::from_secs(3600),
        });
        assert!(limiter.check("c@d.com").is_ok());
        assert!(limiter.check("c@d.com").is_ok());
        assert!(limiter.check("c@d.com").is_err());
    }
}
