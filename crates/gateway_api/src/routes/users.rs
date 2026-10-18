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
    /// TODO(phase-2)：签发 JWT 访问令牌后填充。
    pub token: Option<String>,
}

/// POST /api/users/register —— 201 Created
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), ApiError> {
    let user = state
        .users
        .register(&req.username, &req.email, &req.password)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            user: user.into(),
            token: None,
        }),
    ))
}

/// POST /api/users/login —— 200 OK
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let user = state.users.login(&req.login, &req.password).await?;
    Ok(Json(AuthResponse {
        user: user.into(),
        token: None,
    }))
}
