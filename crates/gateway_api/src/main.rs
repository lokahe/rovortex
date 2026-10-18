//! Rovortex 网关入口：启动 Tokio 运行时并挂载 Axum 路由。
//!
//! 职责边界：本 crate 只做协议适配（HTTP ⇄ 业务调用），
//! 所有业务规则位于 `rovortex-users` 等业务模块。

mod error;
mod routes;
mod state;

use std::net::SocketAddr;

use tracing_subscriber::EnvFilter;

use crate::state::AppState;

#[tokio::main]
async fn main() {
    // 可观测性：RUST_LOG 优先，默认 info 级别。
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // 组合根：在这里注入具体仓储实现（当前为内存实现，数据库落地后仅改此处）。
    let state = AppState::new();
    let app = routes::router(state);

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
    axum::serve(listener, app)
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
