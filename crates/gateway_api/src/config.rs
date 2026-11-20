//! 全部环境变量配置的唯一读取点（组合根用）。
//!
//! 约定：
//! - 每个参数一段：变量名、默认值、解析失败静默回退默认（除密码上下限颠倒 fail fast）
//! - 各业务模块只持有值（config struct），不做环境读取，测试显式传值保持确定性
//! - 重启读取（进程启动时一次），不做热加载

use std::time::Duration;

use rovortex_users::UserServiceConfig;

use crate::mail_rate_limit::MailRateLimitConfig;
use crate::rate_limit::LoginGuardConfig;

// ---- 默认值（与各模块语义绑定，集中列出便于审阅）----

pub const DEFAULT_LOGIN_MAX_FAILURES: u32 = 9;
pub const DEFAULT_LOGIN_LOCK_WINDOW: Duration = Duration::from_secs(15 * 60);
pub const DEFAULT_MAIL_MIN_INTERVAL: Duration = Duration::from_secs(60);
pub const DEFAULT_MAIL_HOURLY_LIMIT: usize = 5;
pub const DEFAULT_MAIL_HOURLY_WINDOW: Duration = Duration::from_secs(3600);
pub const DEFAULT_LOG_BUFFER_CAPACITY: usize = 1000;
pub const DEFAULT_REFRESH_TTL_DAYS: i64 = 30;
pub const DEFAULT_EMAIL_VERIFICATION_TTL_MINS: i64 = 5;
pub const DEFAULT_DELETION_GRACE_DAYS: i64 = 30;
pub const DEFAULT_PASSWORD_MIN_LENGTH: usize = 8;
pub const DEFAULT_PASSWORD_MAX_LENGTH: usize = 128;

/// 解析单个环境变量为可解析类型；未配置或非法返回 None（调用方回退默认）。
fn env_parse<T: std::str::FromStr>(key: &str) -> Option<T> {
    std::env::var(key).ok().and_then(|v| v.parse().ok())
}

pub fn login_guard_config() -> LoginGuardConfig {
    LoginGuardConfig {
        max_failures: env_parse("ROVORTEX_LOGIN_MAX_FAILURES")
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_LOGIN_MAX_FAILURES),
        lock_window: env_parse::<u64>("ROVORTEX_LOGIN_LOCK_WINDOW_SECS")
            .map(Duration::from_secs)
            .filter(|d| !d.is_zero())
            .unwrap_or(DEFAULT_LOGIN_LOCK_WINDOW),
    }
}

pub fn mail_rate_limit_config() -> MailRateLimitConfig {
    MailRateLimitConfig {
        min_interval: env_parse::<u64>("ROVORTEX_MAIL_MIN_INTERVAL_SECS")
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_MAIL_MIN_INTERVAL),
        hourly_limit: env_parse("ROVORTEX_MAIL_HOURLY_LIMIT")
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_MAIL_HOURLY_LIMIT),
        hourly_window: env_parse::<u64>("ROVORTEX_MAIL_HOURLY_WINDOW_SECS")
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_MAIL_HOURLY_WINDOW),
    }
}

pub fn log_buffer_capacity() -> usize {
    env_parse("ROVORTEX_LOG_BUFFER_CAPACITY")
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_LOG_BUFFER_CAPACITY)
}

pub fn users_service_config() -> UserServiceConfig {
    let cfg = UserServiceConfig {
        refresh_ttl_days: env_parse("ROVORTEX_REFRESH_TTL_DAYS")
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_REFRESH_TTL_DAYS),
        email_verification_ttl_mins: env_parse("ROVORTEX_EMAIL_VERIFICATION_TTL_MINS")
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_EMAIL_VERIFICATION_TTL_MINS),
        deletion_grace_days: env_parse("ROVORTEX_DELETION_GRACE_DAYS")
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_DELETION_GRACE_DAYS),
        password_min_length: env_parse("ROVORTEX_PASSWORD_MIN_LENGTH")
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_PASSWORD_MIN_LENGTH),
        password_max_length: env_parse("ROVORTEX_PASSWORD_MAX_LENGTH")
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_PASSWORD_MAX_LENGTH),
    };
    if cfg.password_min_length > cfg.password_max_length {
        // 上下限配置颠倒时快速失败，避免带病启动。
        panic!("ROVORTEX_PASSWORD_MIN_LENGTH must be <= ROVORTEX_PASSWORD_MAX_LENGTH");
    }
    cfg
}
