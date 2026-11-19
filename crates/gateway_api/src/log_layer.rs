//! 把 tracing 事件同步进进程内 LogBuffer 的 subscriber 层。
//!
//! 与 stdout 的 fmt 层并联（registry 组合）：stdout 照常输出，
//! 每条 event 额外格式化后写入 ring buffer + broadcast 给 SSE 订阅者。

use tracing::Event;
use tracing_subscriber::layer::Layer;

use crate::log_buffer::{LogBuffer, LogEntry};

pub struct BufferLayer {
    buffer: LogBuffer,
}

impl BufferLayer {
    pub fn new(buffer: LogBuffer) -> Self {
        Self { buffer }
    }
}

impl<S> Layer<S> for BufferLayer
where
    S: tracing::Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: tracing_subscriber::layer::Context<'_, S>) {
        let meta = event.metadata();
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        let entry = LogEntry {
            ts: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            level: meta.level().to_string(),
            target: meta.target().to_string(),
            message: visitor.message.unwrap_or_default(),
            request_id: visitor.request_id,
            method: visitor.method,
            path: visitor.path,
            status: visitor.status,
            elapsed_ms: visitor.elapsed_ms,
        };

        self.buffer.push(entry);
    }
}

#[derive(Default)]
struct FieldVisitor {
    message: Option<String>,
    request_id: Option<String>,
    method: Option<String>,
    path: Option<String>,
    status: Option<u16>,
    elapsed_ms: Option<u64>,
}

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "message" => self.message = Some(format!("{value:?}")),
            "request_id" => self.request_id = Some(format!("{value:?}")),
            "method" => self.method = Some(format!("{value:?}")),
            "path" => self.path = Some(format!("{value:?}")),
            "status" => {
                self.status = format!("{value:?}").parse().ok();
            }
            "elapsed_ms" => {
                self.elapsed_ms = format!("{value:?}").parse().ok();
            }
            _ => {}
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        match field.name() {
            "status" => self.status = Some(value as u16),
            "elapsed_ms" => self.elapsed_ms = Some(value),
            _ => {}
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "message" => self.message = Some(value.to_string()),
            "request_id" => self.request_id = Some(value.to_string()),
            "method" => self.method = Some(value.to_string()),
            "path" => self.path = Some(value.to_string()),
            _ => {}
        }
    }
}
