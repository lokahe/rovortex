//! 极简 Prometheus 指标（无第三方依赖，1C1G 单实例够用）。
//!
//! 统计维度：route 模板 × method × status 的请求计数与总耗时。
//! 文本格式见 https://prometheus.io/docs/instrumenting/exposition_formats/

use std::collections::HashMap;
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

#[derive(Default)]
pub struct Metrics {
    samples: Mutex<HashMap<LabelKey, Sample>>,
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

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
