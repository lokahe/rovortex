//! 鉴权中间件：校验 `Authorization: Bearer <jwt>`，把用户 id 注入请求扩展。

use axum::extract::{FromRequestParts, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use std::future::Future;

use crate::state::AppState;

/// 经过鉴权中间件后，handler 通过此提取器拿到当前用户 id。
#[derive(Debug, Clone, Copy)]
pub struct AuthUser {
    pub user_id: uuid::Uuid,
}

/// admin 路由专用提取器：在 require_admin 中间件之后使用。
#[derive(Debug, Clone, Copy)]
pub struct AdminUser {
    pub user_id: uuid::Uuid,
}

impl<S> FromRequestParts<S> for AdminUser
where
    S: Send + Sync,
{
    type Rejection = Response;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let admin = parts.extensions.get::<AdminUser>().copied();
        std::future::ready(match admin {
            Some(a) => Ok(a),
            // 走到这里说明路由没挂 require_admin 中间件——配置错误，按 500 报。
            None => Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "admin middleware not installed",
            )
                .into_response()),
        })
    }
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = Response;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let user_id = parts
            .extensions
            .get::<AuthUser>()
            .copied()
            .map(|a| a.user_id);
        std::future::ready(match user_id {
            Some(id) => Ok(AuthUser { user_id: id }),
            // 走到这里说明路由没挂 require_auth 中间件——配置错误，按 500 报。
            None => Err((
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "auth middleware not installed",
            )
                .into_response()),
        })
    }
}

pub async fn require_auth(
    State(state): State<AppState>,
    mut req: axum::extract::Request,
    next: Next,
) -> Result<Response, Response> {
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let Some(token) = token else {
        return Err(unauthorized("missing bearer token"));
    };

    match state.tokens.verify(token) {
        Ok(user_id) => {
            req.extensions_mut().insert(AuthUser { user_id });
            Ok(next.run(req).await)
        }
        Err(_) => Err(unauthorized("invalid or expired token")),
    }
}

/// admin 守卫：先过 JWT，再实时查 is_admin（DB 撤销立即生效，不等 token 过期）。
pub async fn require_admin(
    State(state): State<AppState>,
    mut req: axum::extract::Request,
    next: Next,
) -> Result<Response, Response> {
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let Some(token) = token else {
        return Err(unauthorized("missing bearer token"));
    };

    let user_id = state
        .tokens
        .verify(token)
        .map_err(|_| unauthorized("invalid or expired token"))?;

    match state.users.repository().is_admin(user_id).await {
        Ok(true) => {
            req.extensions_mut().insert(AuthUser { user_id });
            req.extensions_mut().insert(AdminUser { user_id });
            Ok(next.run(req).await)
        }
        Ok(false) => Err(forbidden()),
        Err(_) => Err(forbidden()),
    }
}

fn unauthorized(message: &str) -> Response {
    let body = json!({ "error": { "code": "unauthorized", "message": message } });
    (axum::http::StatusCode::UNAUTHORIZED, Json(body)).into_response()
}

fn forbidden() -> Response {
    let body = json!({
        "error": { "code": "forbidden", "message": "admin privilege required" }
    });
    (axum::http::StatusCode::FORBIDDEN, Json(body)).into_response()
}
