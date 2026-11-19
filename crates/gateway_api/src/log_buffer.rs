//! 进程内日志环形缓冲 + 实时订阅（admin 日志查看页的数据源）。
//!
//! - ring buffer 保留最近 `capacity` 条，内存占用恒定，重启即清空
//!   （访问日志已有 /metrics 与审计表兜底，可接受）
//! - `broadcast` channel 把每条新日志推给所有 SSE 订阅者；
//!   慢消费者（Lagged）直接跳帧，绝不阻塞写路径

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tokio::sync::broadcast;

pub const LOG_BUFFER_CAPACITY: usize = 1000;

#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    /// RFC3339，展示用。
    pub ts: String,
    pub level: String,
    pub target: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
}

impl LogEntry {
    /// 从访问日志事件构造（observe.rs 在请求完成时直接组装，绕过 tracing 层，
    /// 因为 method/path 在 span 字段里，event 层拿不到）。
    pub fn access(
        level: &str,
        target: &str,
        message: String,
        request_id: Option<String>,
        method: Option<String>,
        path: Option<String>,
        status: Option<u16>,
        elapsed_ms: Option<u64>,
    ) -> Self {
        Self {
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            level: level.to_string(),
            target: target.to_string(),
            message,
            request_id,
            method,
            path,
            status,
            elapsed_ms,
        }
    }
}

#[derive(Debug)]
struct Inner {
    entries: Mutex<VecDeque<Arc<LogEntry>>>,
    tx: broadcast::Sender<Arc<LogEntry>>,
}

#[derive(Clone, Debug)]
pub struct LogBuffer {
    inner: Arc<Inner>,
}

/// 日志筛选条件（历史查询与 SSE 订阅共用）。
#[derive(Debug, Default, Clone)]
pub struct LogFilter {
    pub level: Option<String>,
    pub method: Option<String>,
    pub status: Option<u16>,
    pub q: Option<String>,
}

impl LogFilter {
    pub fn matches(&self, e: &LogEntry) -> bool {
        if let Some(level) = &self.level {
            if !e.level.eq_ignore_ascii_case(level) {
                return false;
            }
        }
        if let Some(method) = &self.method {
            if e.method.as_deref() != Some(method.as_str()) {
                return false;
            }
        }
        if let Some(status) = self.status {
            if e.status != Some(status) {
                return false;
            }
        }
        if let Some(q) = &self.q {
            let hay = format!("{} {} {}", e.message, e.target, e.path.clone().unwrap_or_default());
            if !hay.to_lowercase().contains(&q.to_lowercase()) {
                return false;
            }
        }
        true
    }
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity.max(16));
        Self {
            inner: Arc::new(Inner {
                entries: Mutex::new(VecDeque::with_capacity(capacity)),
                tx,
            }),
        }
    }

    /// 写入一条日志：入 ring buffer + 广播给订阅者。永不阻塞、永不失败。
    pub fn push(&self, entry: LogEntry) {
        let entry = Arc::new(entry);
        let mut entries = self.inner.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= LOG_BUFFER_CAPACITY {
            entries.pop_front();
        }
        entries.push_back(entry.clone());
        // 没有订阅者时 send 返回 Err——正常，忽略。
        let _ = self.inner.tx.send(entry);
    }

    /// 按筛选条件返回最近 `limit` 条（时间正序）。
    pub fn snapshot(&self, filter: &LogFilter, limit: usize) -> Vec<Arc<LogEntry>> {
        let entries = self.inner.entries.lock().unwrap_or_else(|e| e.into_inner());
        let matched: Vec<Arc<LogEntry>> = entries
            .iter()
            .filter(|e| filter.matches(e))
            .cloned()
            .collect();
        let start = matched.len().saturating_sub(limit);
        matched[start..].to_vec()
    }

    /// 订阅实时日志（SSE 用）。
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<LogEntry>> {
        self.inner.tx.subscribe()
    }
}
