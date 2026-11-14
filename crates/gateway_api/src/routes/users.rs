//! 用户 HTTP 接口：请求 / 响应 DTO 与 handler。

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
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
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let session = state.users.login(&req.login, &req.password).await?;
    let token = state.tokens.sign(session.user.id)?;
    Ok(Json(AuthResponse {
        user: session.user.into(),
        token,
        refresh_token: session.refresh_token,
        refresh_expires_at: session.refresh_expires_at,
    }))
}
