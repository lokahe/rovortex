//! 路由装配：只做协议适配，业务全部委托给 users 模块。

pub mod auth;
pub mod health;
pub mod session;
pub mod users;
pub mod users_me;

use axum::Router;
use axum::middleware;
use axum::routing::{get, post};

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/users/me", get(users_me::me))
        .route("/api/users/me/password", axum::routing::put(users_me::change_password))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    Router::new()
        .route("/health", get(health::handler))
        .route("/api/users/register", post(users::register))
        .route("/api/users/login", post(users::login))
        .route("/api/auth/refresh", post(session::refresh))
        .route("/api/auth/logout", post(session::logout))
        .merge(protected)
        .with_state(state)
}
