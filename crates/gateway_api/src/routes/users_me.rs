//! 受保护的用户接口：要求有效的 Bearer token。

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use rovortex_users::UserRepository;
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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub email: String,
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
        .ok_or(rovortex_users::UserError::UserNotFound)?;
    Ok(Json(MeResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }))
}
