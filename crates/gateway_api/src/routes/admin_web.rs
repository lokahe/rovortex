//! admin SPA 服务：web/admin 构建产物嵌进二进制，挂 /admin 路由。
//!
//! 约定：vite `base: '/admin/'` 产出资源绝对路径 /admin/assets/...；
//! 本模块把 /admin/{path} 映射到嵌入文件，未命中回 index.html（SPA fallback）。
//! 前端未构建（无 dist）时编译期嵌入为空集，/admin 返回 503 提示。
//!
//! debug 构建走 live reload 特性直接读盘（npm run build 后刷新即生效）；
//! release 构建编译期嵌入，改 UI 必须重编。

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

#[cfg(feature = "admin-web")]
#[derive(rust_embed::RustEmbed)]
#[folder = "$ROVORTEX_ADMIN_DIST"]
struct AdminDist;

/// GET /admin/{*path} —— SPA 静态文件 + fallback。
/// /admin/ 的空 path 场景由 admin_root_index 直接给 index.html。
pub async fn admin_spa(
    axum::extract::Path(path): axum::extract::Path<String>,
) -> Response {
    serve_file(&path)
}

/// GET /admin/ 的 handler：wildcard 不匹配空段，单独处理。
pub async fn admin_index() -> Response {
    serve_file("")
}

fn serve_file(path: &str) -> Response {
    #[cfg(not(feature = "admin-web"))]
    {
        let _ = path;
        return (StatusCode::NOT_IMPLEMENTED, "admin web not built into this binary").into_response();
    }

    #[cfg(feature = "admin-web")]
    {
        // 禁止路径穿越：嵌入文件名不含 ..，直接拒绝带 .. 的请求。
        if path.contains("..") {
            return (StatusCode::BAD_REQUEST, "bad path").into_response();
        }
        // 空路径 = /admin/ 本身 → index.html。
        let file_path = if path.is_empty() { "index.html" } else { path };
        match AdminDist::get(file_path) {
            Some(file) => {
                let mime = mime_type(file_path);
                ([(header::CONTENT_TYPE, mime)], file.data).into_response()
            }
            // SPA fallback：非资产路径（/admin/users 等）回 index.html。
            None => match AdminDist::get("index.html") {
                Some(index) => (
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    index.data,
                )
                    .into_response(),
                None => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "admin dist not embedded (build web/admin first)",
                )
                    .into_response(),
            },
        }
    }
}

fn mime_type(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("map") => "application/json",
        _ => "application/octet-stream",
    }
}

/// GET /admin → 301 /admin/（让相对解析进 SPA）。
pub async fn admin_root() -> Response {
    axum::response::Redirect::to("/admin/").into_response()
}
