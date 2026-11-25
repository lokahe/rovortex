//! 极简 Prometheus 指标（无第三方依赖，1C1G 单实例够用）。
//!
//! 统计维度：route 模板 × method × status 的请求计数与总耗时。
//! 另有按分钟聚合的时间序列（admin 折线图）：内存 ring buffer，重启清零。
//! 文本格式见 https://prometheus.io/docs/instrumenting/exposition_formats/

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

#[derive(Clone, PartialEq, Eq, Hash)]
struct LabelKey {
    route: String,
    method: String,
    status: u16,
}

#[derive(Default)]
struct Sample {
    count: u64,
    total_ms: u64,
}

/// 分钟桶：当前分钟内存活聚合，滚动后进入 history。
#[derive(Default)]
struct MinuteBucket {
    /// 分钟起点（unix 秒，60 对齐）。
    ts: i64,
    count: u64,
    errors: u64,
    total_ms: u64,
}

/// 对外的时间序列点。
#[derive(Debug, Clone, serde::Serialize)]
pub struct HistoryPoint {
    pub ts: i64,
    pub total: u64,
    pub errors: u64,
    pub avg_ms: u64,
}

/// 保留 24 小时（1440 分钟桶）。
const HISTORY_CAPACITY: usize = 1440;

#[derive(Default)]
pub struct Metrics {
    samples: Mutex<HashMap<LabelKey, Sample>>,
    /// 已完成的历史桶（旧→新）+ 当前正在累加的桶。
    history: Mutex<History>,
}

#[derive(Default)]
struct History {
    done: VecDeque<HistoryPoint>,
    current: MinuteBucket,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe(&self, route: &str, method: &str, status: u16, elapsed_ms: u64) {
        let key = LabelKey {
            route: route.to_string(),
            method: method.to_string(),
            status,
        };
        let mut map = self.samples.lock().unwrap();
        let s = map.entry(key).or_default();
        s.count += 1;
        s.total_ms += elapsed_ms;
        drop(map);

        // 分钟桶累加：桶过期则滚动（顺带在这里做，省一个独立定时任务）。
        let mut h = self.history.lock().unwrap();
        let now_min = chrono::Utc::now().timestamp() / 60 * 60;
        if h.current.ts != now_min {
            roll(&mut h, now_min);
        }
        h.current.count += 1;
        if status >= 400 {
            h.current.errors += 1;
        }
        h.current.total_ms += elapsed_ms;
    }

    /// admin 折线图：最近 minutes 分钟的点（旧→新），不足处补零点。
    pub fn history(&self, minutes: u32) -> Vec<HistoryPoint> {
        let minutes = minutes.clamp(1, HISTORY_CAPACITY as u32) as i64;
        let h = self.history.lock().unwrap();
        let now_min = chrono::Utc::now().timestamp() / 60 * 60;
        let start_min = now_min - (minutes - 1) * 60;
        let by_ts: HashMap<i64, &HistoryPoint> =
            h.done.iter().map(|p| (p.ts, p)).collect();

        let mut out = Vec::with_capacity(minutes as usize);
        for i in 0..minutes {
            let ts = start_min + i * 60;
            match by_ts.get(&ts) {
                Some(p) => out.push((*p).clone()),
                None => out.push(HistoryPoint { ts, total: 0, errors: 0, avg_ms: 0 }),
            }
        }
        // 当前未完成桶也给出（前端实时点）。
        if h.current.ts >= start_min {
            let c = &h.current;
            out.push(HistoryPoint {
                ts: c.ts,
                total: c.count,
                errors: c.errors,
                avg_ms: if c.count > 0 { c.total_ms / c.count } else { 0 },
            });
        }
        out
    }

    /// SSE live 快照：当前分钟桶增量。
    pub fn current(&self) -> HistoryPoint {
        let h = self.history.lock().unwrap();
        let c = &h.current;
        HistoryPoint {
            ts: c.ts,
            total: c.count,
            errors: c.errors,
            avg_ms: if c.count > 0 { c.total_ms / c.count } else { 0 },
        }
    }

    /// Prometheus 文本格式输出。
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP rovortex_http_requests_total Total HTTP requests.\n");
        out.push_str("# TYPE rovortex_http_requests_total counter\n");
        out.push_str("# HELP rovortex_http_request_duration_ms_sum Total request duration in milliseconds.\n");
        out.push_str("# TYPE rovortex_http_request_duration_ms_sum counter\n");

        let map = self.samples.lock().unwrap();
        // 稳定输出顺序，便于肉眼比对与 diff。
        let mut keys: Vec<_> = map.keys().collect();
        keys.sort_by(|a, b| (&a.route, &a.method).cmp(&(&b.route, &b.method)));
        for k in keys {
            let s = &map[k];
            let labels = format!(
                "route=\"{}\",method=\"{}\",status=\"{}\"",
                escape(&k.route),
                escape(&k.method),
                k.status
            );
            out.push_str(&format!(
                "rovortex_http_requests_total{{{labels}}} {}\n",
                s.count
            ));
            out.push_str(&format!(
                "rovortex_http_request_duration_ms_sum{{{labels}}} {}\n",
                s.total_ms
            ));
        }
        out
    }
}

/// 把过期桶固化进 done；新桶从 ts 重新计数。
fn roll(h: &mut History, now_min: i64) {
    let c = &h.current;
    if c.ts > 0 {
        h.done.push_back(HistoryPoint {
            ts: c.ts,
            total: c.count,
            errors: c.errors,
            avg_ms: if c.count > 0 { c.total_ms / c.count } else { 0 },
        });
        while h.done.len() > HISTORY_CAPACITY {
            h.done.pop_front();
        }
    }
    h.current = MinuteBucket { ts: now_min, ..Default::default() };
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_accumulates_per_minute() {
        let m = Metrics::new();
        m.observe("/health", "GET", 200, 5);
        m.observe("/health", "GET", 200, 15);
        m.observe("/x", "GET", 500, 100);
        let cur = m.current();
        assert_eq!(cur.total, 3);
        assert_eq!(cur.errors, 1);
        assert_eq!(cur.avg_ms, 40);
    }

    #[test]
    fn history_pads_missing_minutes() {
        let m = Metrics::new();
        m.observe("/health", "GET", 200, 10);
        let pts = m.history(5);
        assert_eq!(pts.len(), 6); // 5 个补零 + 当前桶
        // 只有最后一个（当前桶）非零。
        assert!(pts[..5].iter().all(|p| p.total == 0));
        assert_eq!(pts[5].total, 1);
    }
}
