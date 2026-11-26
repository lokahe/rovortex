//! Rovortex 网关入口：启动 Tokio 运行时并挂载 Axum 路由。
//!
//! 职责边界：本 crate 只做协议适配（HTTP ⇄ 业务调用），
//! 所有业务规则位于 `rovortex-users` 等业务模块。

mod config;
mod error;
mod jobs;
mod log_buffer;
mod log_layer;
mod mail_rate_limit;
mod metrics;
mod observe;
mod rate_limit;
mod routes;
mod state;

use std::net::SocketAddr;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

use crate::state::AppState;

#[tokio::main]
async fn main() {
    // 可观测性：RUST_LOG 优先，默认 info 级别。
    // registry 组合：stdout fmt 层照常输出 + BufferLayer 同步进进程内 ring buffer
    // （admin 日志页数据源；buffer 要先于 subscriber 存在，故先构造再装）。
    let log_buffer = crate::log_buffer::LogBuffer::new(crate::config::log_buffer_capacity());
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        ))
        .with(crate::log_layer::BufferLayer::new(log_buffer.clone()))
        .init();
    // 组合根：在这里注入具体仓储实现（当前为 PostgreSQL，含启动时迁移）。
    let state = AppState::with_log_buffer(log_buffer.clone()).await;
    let app = routes::router(state.clone()).layer(cors_layer()).layer(
        axum::middleware::from_fn_with_state(state.clone(), observe::request_id_and_log),
    );

    let port: u16 = std::env::var("ROVORTEX_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    tracing::info!("Rovortex gateway listening on http://{addr}");

    // 优雅停机：Ctrl-C 后停止接收新连接，等待存量请求完成。
    // with_connect_info：login 限流需要客户端地址（ConnectInfo 提取器）。
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .expect("server error");
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl-C handler");
    tracing::info!("shutdown signal received, draining connections...");
}

/// CORS：允许名单来自 ROVORTEX_CORS_ORIGINS（逗号分隔）；
/// 未配置时不放行任何跨域（API 由同源 App/页面消费，默认最严）。
/// 浏览器 admin 前端（如 admin.lokahe.top）配好后即可直调。
fn cors_layer() -> tower_http::cors::CorsLayer {
    use axum::http::HeaderValue;

    let origins: Vec<HeaderValue> = std::env::var("ROVORTEX_CORS_ORIGINS")
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .filter_map(|o| o.parse().ok())
                .collect()
        })
        .unwrap_or_default();

    if origins.is_empty() {
        tower_http::cors::CorsLayer::new()
    } else {
        tower_http::cors::CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
            ])
            .allow_headers([
                axum::http::header::AUTHORIZATION,
                axum::http::header::CONTENT_TYPE,
            ])
    }
}
