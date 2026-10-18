//! 业务错误 → HTTP 响应映射。

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rovortex_users::UserError;
use serde_json::json;

/// 统一错误体：`{"error": {"code": "...", "message": "..."}}`
pub struct ApiError(pub UserError);

impl From<UserError> for ApiError {
    fn from(e: UserError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self.0 {
            UserError::UsernameTaken(_) | UserError::EmailTaken(_) => {
                (StatusCode::CONFLICT, "conflict")
            }
            UserError::InvalidUsername(_)
            | UserError::InvalidEmail(_)
            | UserError::InvalidPassword(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            UserError::UserNotFound => (StatusCode::NOT_FOUND, "user_not_found"),
            UserError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            UserError::Hashing(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self.0, "internal error while handling user request");
        } else {
            tracing::debug!(error = %self.0, "user request failed");
        }

        let body = json!({
            "error": { "code": code, "message": self.0.to_string() }
        });
        (status, Json(body)).into_response()
    }
}
