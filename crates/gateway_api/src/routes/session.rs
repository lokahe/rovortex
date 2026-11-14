//! 会话续期与登出接口。

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use rovortex_users::User;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::routes::users::AuthResponse;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}

fn auth_response(
    tokens: &rovortex_users::TokenSigner,
    user: User,
    refresh_token: String,
    refresh_expires_at: DateTime<Utc>,
) -> Result<AuthResponse, ApiError> {
    let token = tokens.sign(user.id)?;
    Ok(AuthResponse {
        user: user.into(),
        token,
        refresh_token,
        refresh_expires_at,
    })
}

/// POST /api/auth/refresh —— 200 OK（轮换：旧 refresh token 作废）
pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let session = state.users.refresh(&req.refresh_token).await?;
    Ok(Json(auth_response(
        &state.tokens,
        session.user,
        session.refresh_token,
        session.refresh_expires_at,
    )?))
}

/// POST /api/auth/logout —— 204 No Content（幂等）
pub async fn logout(
    State(state): State<AppState>,
    Json(req): Json<LogoutRequest>,
) -> Result<StatusCode, ApiError> {
    state.users.logout(&req.refresh_token).await?;
    Ok(StatusCode::NO_CONTENT)
}
