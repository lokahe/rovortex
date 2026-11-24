//! 统一邮箱入口（登录/注册合一）：邮箱+密码一框，设计见 docs/EMAIL_ENTRY.md。
//!
//! request 响应只有两种：200（凭据有效，直接登录）/ 202（其余一切，已发验证邮件）。
//! 防枚举语义由 service 层保证（每个合法邮箱都"发信"，封禁/注销走哑路径）。
//! confirm 限流复用 ConfirmCodeLimiter（每 ip+email 5 次 / 15 分钟）。

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use std::net::SocketAddr;

use crate::error::ApiError;
use crate::routes::users::{AuthResponse, client_ip, session_context};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct EmailEntryRequest {
    pub email: String,
    /// 可空：OAuth 风格无密入口走码验证路径。
    #[serde(default)]
    pub password: String,
}

/// 平台自报头：app/android → 码+dp；其余（缺省 web）→ 码+PC 链接。
/// 伪造只影响自己收到的邮件内容，无攻击面。
fn client_platform(headers: &HeaderMap) -> String {
    headers
        .get("x-client-platform")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "web".into())
}

/// POST /api/auth/email-entry —— 200（直接登录）或 202（验证邮件已发）。
pub async fn request_entry(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<EmailEntryRequest>,
) -> Result<Response, ApiError> {
    let ip = client_ip(&headers, addr);
    let platform = client_platform(&headers);
    let session = state
        .users
        .request_email_entry(
            &req.email,
            &req.password,
            &platform,
            &ip,
            &session_context(&headers, addr),
        )
        .await?;
    match session {
        Some(s) => {
            let token = state.tokens.sign(s.user.id)?;
            Ok((
                StatusCode::OK,
                Json(AuthResponse {
                    user: s.user.into(),
                    token,
                    refresh_token: s.refresh_token,
                    refresh_expires_at: s.refresh_expires_at,
                }),
            )
                .into_response())
        }
        None => Ok(StatusCode::ACCEPTED.into_response()),
    }
}

#[derive(Debug, Deserialize)]
pub struct EmailEntryConfirmRequest {
    pub email: String,
    /// 6 位数字验证码。
    pub code: String,
    /// 可选：confirm 时静默设置/更新密码（收码=邮箱控制权）。
    /// 未注册账号建号时必填。
    #[serde(default)]
    pub password: Option<String>,
}

/// POST /api/auth/email-entry/confirm —— 201 Created（验证码确认：登录或建号）。
pub async fn confirm_entry(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<EmailEntryConfirmRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), ApiError> {
    let ip = client_ip(&headers, addr);
    let key = format!("{}|{}", ip, req.email.to_lowercase());
    if let Err(reason) = state.confirm_code_limiter.check(&key) {
        return Err(ApiError::too_many_requests(reason));
    }
    let session = state
        .users
        .confirm_email_entry(
            &req.email,
            &req.code,
            req.password.as_deref(),
            &ip,
            &session_context(&headers, addr),
        )
        .await?;
    let token = state.tokens.sign(session.user.id)?;
    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            user: session.user.into(),
            token,
            refresh_token: session.refresh_token,
            refresh_expires_at: session.refresh_expires_at,
        }),
    ))
}
