//! 可观测性中间件：request_id 贯穿 + 访问日志 + HTTP 指标。
//!
//! 每个请求一行结构化日志（method / path / status / 耗时），
//! request_id 同时回写到响应头 `x-request-id`，便于客户端报障时对账。

use axum::extract::State;
use axum::http::header::HeaderName;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use tracing::{info_span, Instrument};

use crate::state::AppState;

pub const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// 入口中间件：确定 request_id → 开 tracing span（后续所有日志自动携带）→
/// 记录耗时 + 按“路由模板”统计指标。
pub async fn request_id_and_log(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    // 优先沿用上游（如网关/反代）给定的 id，否则生成。
    let request_id = req
        .headers()
        .get(&X_REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(new_request_id);

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // /metrics 自身不统计，避免自指增长。
    let track = path != "/metrics";

    let span = info_span!(
        "http_request",
        request_id = %request_id,
        method = %method,
        path = %path,
    );
    // 用 instrument 而非 enter()：enter 的 guard 跨 await 挂起时，
    // 恢复后线程局部上下文可能丢失（任务被调度到其他线程），
    // 导致 await 之后的日志没有 span 字段。instrument 在每次恢复时重挂。
    let start = std::time::Instant::now();
    let mut response = async {
        let response = next.run(req).await;
        let elapsed_ms = start.elapsed().as_millis() as u64;

        let status = response.status();
        tracing::info!(
            status = status.as_u16(),
            elapsed_ms,
            "request completed"
        );

        // 失败请求在 INFO 日志之上多一行 ERROR，排障时先看到它。
        if status.is_server_error() {
            tracing::error!(status = status.as_u16(), "request failed with server error");
        }

        if track {
            state.metrics.observe(
                &route_template(&path),
                method.as_str(),
                status.as_u16(),
                elapsed_ms,
            );
        }

        response
    }
    .instrument(span.clone())
    .await;

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(X_REQUEST_ID, value);
    }
    response
}

/// 路径 → 路由模板：把 UUID 等路径参数归一成 `:id`，让指标标签基数可控。
fn route_template(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for seg in path.split('/') {
        if seg.is_empty() {
            continue;
        }
        if seg.len() == 36 && seg.chars().filter(|c| *c == '-').count() == 4 {
            out.push_str("/:id");
        } else {
            out.push('/');
            out.push_str(seg);
        }
    }
    out
}

/// 128-bit 混合熵取 hex 前 16 位；单实例 QPS 下碰撞概率可忽略。
fn new_request_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let mix = nanos ^ (pid << 96) ^ (nanos.wrapping_mul(0x9E3779B97F4A7C15));
    format!("{mix:016x}")
}
