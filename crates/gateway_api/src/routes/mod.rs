//! 路由装配：只做协议适配，业务全部委托给 users 模块。

pub mod health;
pub mod users;

use axum::Router;
use axum::routing::{get, post};

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health::handler))
        .route("/api/users/register", post(users::register))
        .route("/api/users/login", post(users::login))
        .with_state(state)
}
