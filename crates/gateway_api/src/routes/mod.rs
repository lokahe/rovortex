//! 路由装配：只做协议适配，业务全部委托给 users 模块。

pub mod admin;
pub mod auth;
pub mod db;
pub mod health;
pub mod magic;
pub mod metrics;
pub mod oauth;
pub mod password_reset;
pub mod session;
pub mod users;
pub mod users_me;
pub mod verify_email;

use axum::Router;
use axum::middleware;
use axum::routing::{get, post, put};

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/users/me", get(users_me::me))
        .route("/api/users/me/password", put(users_me::change_password))
        .route("/api/users/me/email", put(users_me::change_email))
        .route("/api/users/me/username", put(users_me::change_username))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    let admin_routes = Router::new()
        .route("/api/admin/users", get(admin::list_users))
        .route("/api/admin/users/{id}", get(admin::user_detail))
        .route("/api/admin/users/{id}/ban", put(admin::set_ban))
        .route("/api/admin/stats", get(admin::stats))
        .route("/api/admin/db/tables", get(db::list_tables))
        .route("/api/admin/db/tables/{table}", get(db::browse))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_admin,
        ));

    Router::new()
        .route("/health", get(health::handler))
        .route("/metrics", get(metrics::handler))
        .route("/api/users/register", post(users::register))
        .route("/api/users/login", post(users::login))
        .route("/api/auth/refresh", post(session::refresh))
        .route("/api/auth/logout", post(session::logout))
        .route("/api/auth/verify-email/request", post(verify_email::request_verification))
        .route("/api/auth/verify-email/confirm", get(verify_email::confirm))
        .route("/api/auth/email-change/confirm", get(verify_email::confirm_email_change))
        .route("/api/auth/oauth/github", get(oauth::github_authorize))
        .route("/api/auth/oauth/github/callback", get(oauth::github_callback))
        .route("/api/auth/magic-link", post(magic::request_magic_link))
        .route("/api/auth/magic-link/verify", get(magic::verify_magic_link))
        .route("/api/auth/password-reset/request", post(password_reset::request_reset))
        .route("/api/auth/password-reset/confirm", get(password_reset::confirm_form).post(password_reset::confirm_submit))
        .merge(protected)
        .merge(admin_routes)
        .with_state(state)
}
