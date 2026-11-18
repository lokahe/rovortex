//! 邮箱验证接口：请求验证信 / 点击确认链接。

use axum::extract::{ConnectInfo, Query, State};
use axum::http::StatusCode;
use std::net::SocketAddr;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::error::ApiError;
use crate::routes::users::client_ip;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmParams {
    pub token: String,
}

/// POST /api/auth/verify-email/request —— 202 Accepted（防枚举：恒 202）
pub async fn request_verification(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<VerifyEmailRequest>,
) -> Result<StatusCode, ApiError> {
    let ip = client_ip(&headers, addr);
    state
        .users
        .request_email_verification(&req.email, &ip)
        .await?;
    Ok(StatusCode::ACCEPTED)
}

/// GET /api/auth/verify-email/confirm?token=... —— 200 结果页
pub async fn confirm(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Query(params): Query<ConfirmParams>,
) -> Result<Response, Response> {
    let ip = client_ip(&headers, addr);
    match state.users.confirm_email_verification(&params.token, &ip).await {
        Ok(()) => Ok(result_page("验证成功", "你的邮箱已完成验证，可以关闭此页面。")),
        Err(_) => Err(result_page(
            "链接无效",
            "验证链接无效或已过期，请重新请求验证邮件。",
        )),
    }
}

/// GET /api/auth/email-change/confirm?token=... —— 200 结果页
pub async fn confirm_email_change(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Query(params): Query<ConfirmParams>,
) -> Result<Response, Response> {
    let ip = client_ip(&headers, addr);
    match state.users.confirm_email_change(&params.token, &ip).await {
        Ok(()) => Ok(result_page("变更成功", "你的账号邮箱已更新。")),
        Err(_) => Err(result_page(
            "链接无效",
            "确认链接无效或已过期，请重新发起邮箱变更。",
        )),
    }
}

/// 极简结果页（无前端依赖，直接由 API 服务渲染）。
fn result_page(title: &str, detail: &str) -> Response {
    let body = format!(
        r#"<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8"><title>{title}</title></head>
<body style="font-family:sans-serif;text-align:center;padding-top:80px">
<h1>{title}</h1><p style="color:#666">{detail}</p>
</body></html>"#
    );
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}
