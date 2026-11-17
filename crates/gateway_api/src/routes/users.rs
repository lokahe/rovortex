//! 用户 HTTP 接口：请求 / 响应 DTO 与 handler。

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use std::net::SocketAddr;
use chrono::{DateTime, Utc};
use rovortex_users::User;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// 用户名或邮箱。
    pub login: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            email: u.email,
            created_at: u.created_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    /// JWT access token（HS256，2 小时有效期）。
    pub token: String,
    /// 明文 refresh token：客户端妥善保存，用于换取新 access token。
    pub refresh_token: String,
    pub refresh_expires_at: DateTime<Utc>,
}

/// POST /api/users/register —— 201 Created
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), ApiError> {
    let session = state
        .users
        .register(&req.username, &req.email, &req.password)
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

/// POST /api/users/login —— 200 OK
///
/// 限流键 (client_ip, login)：连续失败 5 次锁 15 分钟。
/// 客户端 IP 取 X-Forwarded-For 首段（Caddy 反代注入），回退 ConnectInfo。
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let ip = client_ip(&headers, addr);
    let key = rovortex_users::guard_key(&ip, &req.login);
    let session = state.users.login(&key, &req.login, &req.password).await?;
    let token = state.tokens.sign(session.user.id)?;
    Ok(Json(AuthResponse {
        user: session.user.into(),
        token,
        refresh_token: session.refresh_token,
        refresh_expires_at: session.refresh_expires_at,
    }))
}

/// Caddy 反代会覆盖 X-Forwarded-For 为真实客户端地址；直连时回退 socket 地址。
fn client_ip(headers: &axum::http::HeaderMap, addr: SocketAddr) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string())
}
