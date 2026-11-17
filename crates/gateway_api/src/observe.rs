//! 可观测性中间件：request_id 贯穿 + 访问日志。
//!
//! 每个请求一行结构化日志（method / path / status / 耗时），
//! request_id 同时回写到响应头 `x-request-id`，便于客户端报障时对账。

use axum::http::header::HeaderName;
use axum::middleware::Next;
use axum::response::Response;
use tracing::info_span;

pub const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// 入口中间件：确定 request_id → 开 tracing span（后续所有日志自动携带）→ 记录耗时。
pub async fn request_id_and_log(
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

    let span = info_span!(
        "http_request",
        request_id = %request_id,
        method = %method,
        path = %path,
    );
    let _guard = span.enter();

    let start = std::time::Instant::now();
    let mut response = next.run(req).await;
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

    if let Ok(value) = axum::http::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(X_REQUEST_ID, value);
    }
    response
}

/// 128-bit 随机性取 hex 前 16 位；碰撞概率在单实例 QPS 下可忽略。
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
