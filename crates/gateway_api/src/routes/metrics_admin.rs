//! admin 折线图数据源：历史查询 + SSE 实时推送。
//!
//! 数据来自进程内 Metrics 的分钟桶（重启清零，不落库）；
//! 挂在 require_admin 组内与其他 admin 端点同权鉴权。

use std::convert::Infallible;
use std::time::Duration;

use axum::Json;
use axum::extract::{Query, State};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use futures_util::Stream;
use serde::Deserialize;

use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    minutes: Option<u32>,
}

/// GET /api/admin/metrics/history?minutes=60 —— 最近 N 分钟逐分钟点（旧→新，末尾含当前桶）。
pub async fn history(
    State(state): State<AppState>,
    Query(q): Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    let points = state.metrics.history(q.minutes.unwrap_or(60));
    Json(serde_json::json!({ "points": points }))
}

/// GET /api/admin/metrics/live —— SSE 每 5s 推当前分钟桶快照。
pub async fn stream_live(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let metrics = state.metrics.clone();

    let stream = futures_util::stream::unfold(
        (metrics, tokio::time::interval(Duration::from_secs(5))),
        |(metrics, mut timer)| async move {
            // interval 首个 tick 立即到期：客户端连上即收到一份快照。
            timer.tick().await;
            let point = metrics.current();
            let json = serde_json::to_string(&point).unwrap_or_default();
            let event = SseEvent::default().event("point").data(json);
            Some((Ok(event), (metrics, timer)))
        },
    );

    Sse::new(stream).keep_alive(KeepAlive::default())
}
