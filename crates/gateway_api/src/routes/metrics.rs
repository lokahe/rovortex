//! /metrics —— Prometheus 拉取端点。
//!
//! 公网可达（与 API 同入口）。标签基数受控（路由模板归一化），无敏感数据。

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

/// GET /metrics —— 200 text/plain; version=0.0.4
pub async fn handler(State(state): State<AppState>) -> Response {
    let body = state.metrics.render();
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}
