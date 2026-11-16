//! 受保护的用户接口：要求有效的 Bearer token。

use axum::Json;
use axum::extract::State;
use chrono::{DateTime, Utc};
use rovortex_users::UserError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::routes::auth::AuthUser;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize)]
pub struct ChangeEmailRequest {
    pub new_email: String,
}

/// GET /api/users/me —— 200 OK
pub async fn me(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<MeResponse>, ApiError> {
    let user = state
        .users
        .repository()
        .find_by_id(auth.user_id)
        .await?
        .ok_or(UserError::UserNotFound)?;
    Ok(Json(MeResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        email_verified: user.email_verified,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }))
}

/// PUT /api/users/me/password —— 204 No Content（成功后全部会话失效）
pub async fn change_password(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<axum::http::StatusCode, ApiError> {
    state
        .users
        .change_password(auth.user_id, &req.old_password, &req.new_password)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// PUT /api/users/me/email —— 202 Accepted（确认链接发到新邮箱，防枚举恒 202）
pub async fn change_email(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<ChangeEmailRequest>,
) -> Result<axum::http::StatusCode, ApiError> {
    state
        .users
        .request_email_change(auth.user_id, &req.new_email)
        .await?;
    Ok(axum::http::StatusCode::ACCEPTED)
}
