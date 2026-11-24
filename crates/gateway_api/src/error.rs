//! 业务错误 → HTTP 响应映射。

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use rovortex_users::UserError;
use serde_json::json;

/// 统一错误：领域错误（UserError 映射）+ HTTP 协议层错误（OAuth 流程等）。
#[derive(Debug)]
pub enum ApiError {
    Domain(UserError),
    /// OAuth / 协议层错误：直接指定状态码与错误码。
    Http(StatusCode, &'static str, String),
}

impl From<UserError> for ApiError {
    fn from(e: UserError) -> Self {
        Self::Domain(e)
    }
}

impl ApiError {
    pub fn bad_request(message: String) -> Self {
        Self::Http(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    pub fn not_found() -> Self {
        Self::Http(
            StatusCode::NOT_FOUND,
            "not_found",
            "resource not found".to_string(),
        )
    }

    pub fn internal(message: String) -> Self {
        Self::Http(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }

    pub fn too_many_requests(message: impl Into<String>) -> Self {
        Self::Http(
            StatusCode::TOO_MANY_REQUESTS,
            "too_many_requests",
            message.into(),
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            ApiError::Http(status, code, message) => (status, code, message),
            ApiError::Domain(e) => {
                let (status, code) = match &e {
                    UserError::UsernameTaken(_) | UserError::EmailTaken(_) => {
                        (StatusCode::CONFLICT, "conflict")
                    }
                    UserError::InvalidUsername(_)
                    | UserError::InvalidEmail(_)
                    | UserError::InvalidPassword(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
                    UserError::UserNotFound => (StatusCode::NOT_FOUND, "user_not_found"),
                    UserError::InvalidCredentials | UserError::InvalidRefreshToken => {
                        (StatusCode::UNAUTHORIZED, "invalid_credentials")
                    }
                    UserError::InvalidSignupCode => {
                        (StatusCode::UNAUTHORIZED, "invalid_signup_code")
                    }
                    UserError::TooManyAttempts => {
                        (StatusCode::TOO_MANY_REQUESTS, "too_many_attempts")
                    }
                    UserError::AccountBanned => (StatusCode::FORBIDDEN, "account_banned"),
                    UserError::AccountDeleted => (StatusCode::FORBIDDEN, "account_deleted"),
                    UserError::LastLoginMethod => (StatusCode::CONFLICT, "last_login_method"),
                    UserError::Hashing(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
                };
                (status, code, e.to_string())
            }
        };

        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(code, %message, "internal error while handling user request");
        } else {
            tracing::debug!(code, %message, "user request failed");
        }

        let body = json!({
            "error": { "code": code, "message": message }
        });
        (status, Json(body)).into_response()
    }
}
