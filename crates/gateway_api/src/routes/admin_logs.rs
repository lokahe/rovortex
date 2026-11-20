//! admin 日志查看：历史查询 + SSE 实时流。
//!
//! 数据源是进程内 LogBuffer（ring buffer + broadcast），
//! 无 DB 参与，挂在 require_admin 组内与其他 admin 端点同权鉴权。

use std::convert::Infallible;

use axum::extract::{Query, State};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::Json;
use futures_util::Stream;
use serde::Deserialize;

use crate::log_buffer::LogFilter;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    level: Option<String>,
    method: Option<String>,
    status: Option<u16>,
    q: Option<String>,
    limit: Option<usize>,
}

fn filter_of(q: &LogsQuery) -> LogFilter {
    LogFilter {
        level: q.level.clone(),
        method: q.method.clone(),
        status: q.status,
        q: q.q.clone(),
    }
}

/// GET /api/admin/logs —— 最近日志（默认 200 条，最大为 buffer 容量）。
pub async fn list_logs(
    State(state): State<AppState>,
    Query(q): Query<LogsQuery>,
) -> Json<serde_json::Value> {
    let limit = q.limit.unwrap_or(200).min(state.log_buffer.capacity());
    let entries = state.log_buffer.snapshot(&filter_of(&q), limit);
    Json(serde_json::json!({ "logs": entries }))
}

/// GET /api/admin/logs/stream —— SSE 实时日志流（同一组筛选参数）。
pub async fn stream_logs(
    State(state): State<AppState>,
    Query(q): Query<LogsQuery>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = state.log_buffer.subscribe();
    let filter = filter_of(&q);
    let buffer = state.log_buffer.clone();

    let stream = futures_util::stream::unfold(
        (rx, filter, buffer),
        |(mut rx, filter, buffer)| async move {
            loop {
                match rx.recv().await {
                    Ok(entry) => {
                        if filter.matches(&entry) {
                            let json = serde_json::to_string(&entry).unwrap_or_default();
                            let event = SseEvent::default()
                                .event("log")
                                .data(json);
                            return Some((Ok(event), (rx, filter, buffer)));
                        }
                        // 不匹配筛选：继续等下一条。
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // 消费慢了跳帧：发一条提示，前端可显示「已省略 N 条」。
                        let event = SseEvent::default()
                            .event("lagged")
                            .data("{}");
                        return Some((Ok(event), (rx, filter, buffer)));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        // buffer 被回收（进程退出），终止流。
                        return None;
                    }
                }
            }
        },
    );

    Sse::new(stream).keep_alive(KeepAlive::default())
}
