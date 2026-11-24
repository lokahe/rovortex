//! Magic Link 免密登录：发信 + 验证签会话。

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use serde::Deserialize;
use std::net::SocketAddr;

use crate::error::ApiError;
use crate::routes::session::auth_response;
use crate::routes::users::client_ip;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct MagicLinkRequest {
    pub email: String,
}

/// POST /api/auth/magic-link —— 请求登录邮件。
///
/// 防枚举：无论邮箱是否注册都返回 202（未注册邮箱的登录即注册在 verify 一步发生）。
pub async fn request_magic_link(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<MagicLinkRequest>,
) -> Result<StatusCode, ApiError> {
    let ip = client_ip(&headers, addr);
    // 频率限制：超限 429，与登录限流语义一致
    if let Err(reason) = state.mail_limiter.check(&req.email) {
        return Err(ApiError::too_many_requests(reason));
    }
    state.users.request_magic_link(&req.email, &ip).await?;
    Ok(StatusCode::ACCEPTED)
}

/// GET /api/auth/magic-link/verify?token=... —— 点击邮件链接登录。
pub async fn verify_magic_link(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<VerifyQuery>,
) -> Result<Json<crate::routes::users::AuthResponse>, ApiError> {
    let ip = client_ip(&headers, addr);
    let ctx = crate::routes::users::session_context(&headers, addr);
    let session = state
        .users
        .verify_magic_link(&query.token, &ip, &ctx)
        .await?;
    let auth = auth_response(
        &state.tokens,
        session.user,
        session.refresh_token,
        session.refresh_expires_at,
    )?;
    Ok(Json(auth))
}

#[derive(Debug, Deserialize)]
pub struct VerifyQuery {
    pub token: String,
}
