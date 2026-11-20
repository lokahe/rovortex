//! 账号注销（软删 + 冷静期）与恢复。
//!
//! - POST /api/auth/account/delete（登录态）：发注销确认邮件
//! - GET  /api/auth/account/confirm-deletion?token=...（邮件链接）：确认注销，渲染结果页
//! - POST /api/auth/account/recover（匿名）：向原邮箱发恢复链接（防枚举恒 202）
//! - GET  /api/auth/account/confirm-recovery?token=...（邮件链接）：确认恢复
//!
//! 页面渲染复用 password_reset.rs 的极简 HTML 风格。

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use std::net::SocketAddr;

use crate::error::ApiError;
use crate::routes::auth::AuthUser;
use crate::routes::password_reset::{error_page, result_page};
use crate::routes::users::client_ip;
use crate::state::AppState;

/// POST /api/auth/account/delete —— 202 Accepted（确认邮件已发送）。
pub async fn request_deletion(
    State(state): State<AppState>,
    auth: AuthUser,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let ip = client_ip(&headers, addr);
    state.users.request_account_deletion(auth.user_id, &ip).await?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(Debug, Deserialize)]
pub struct ConfirmParams {
    pub token: String,
}

/// GET /api/auth/account/confirm-deletion?token=... —— 邮件链接落地：确认注销。
pub async fn confirm_deletion(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<ConfirmParams>,
) -> Result<axum::response::Response, axum::response::Response> {
    let ip = client_ip(&headers, addr);
    match state
        .users
        .confirm_account_deletion(&params.token, &ip)
        .await
    {
        Ok(()) => Ok(result_page(
            "账号已注销",
            "你的账号已进入 30 天冷静期，期间可用原邮箱请求恢复；逾期数据将被彻底删除。",
        )),
        Err(_) => Err(error_page(
            "注销失败",
            "链接无效或已过期，请重新在设置页发起注销。",
        )),
    }
}

#[derive(Debug, Deserialize)]
pub struct RecoveryRequest {
    pub email: String,
}

/// POST /api/auth/account/recover —— 202 Accepted（防枚举：恒 202）。
pub async fn request_recovery(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RecoveryRequest>,
) -> Result<StatusCode, ApiError> {
    let ip = client_ip(&headers, addr);
    if let Err(reason) = state.mail_limiter.check(&req.email) {
        return Err(ApiError::too_many_requests(reason));
    }
    state
        .users
        .request_account_recovery(&req.email, &ip)
        .await?;
    Ok(StatusCode::ACCEPTED)
}

/// GET /api/auth/account/confirm-recovery?token=... —— 邮件链接落地：确认恢复。
pub async fn confirm_recovery(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<ConfirmParams>,
) -> Result<axum::response::Response, axum::response::Response> {
    let ip = client_ip(&headers, addr);
    match state
        .users
        .confirm_account_recovery(&params.token, &ip)
        .await
    {
        Ok(()) => Ok(result_page(
            "账号已恢复",
            "账号已恢复正常，现在可以使用原方式登录。",
        )),
        Err(_) => Err(error_page(
            "恢复失败",
            "链接无效、已过期或账号已过冷静期，数据可能已被删除。",
        )),
    }
}
