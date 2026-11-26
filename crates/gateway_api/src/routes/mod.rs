//! 路由装配：只做协议适配，业务全部委托给 users 模块。

pub mod account;
pub mod admin;
pub mod admin_logs;
pub mod admin_web;
pub mod auth;
pub mod config;
pub mod db;
pub mod email_entry;
pub mod health;
pub mod jobs;
pub mod magic;
pub mod metrics;
pub mod metrics_admin;
pub mod oauth;
pub mod password_reset;
pub mod session;
pub mod signup;
pub mod users;
pub mod users_me;
pub mod verify_email;

use axum::Router;
use axum::middleware;
use axum::routing::{delete, get, patch, post, put};

use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/users/me", get(users_me::me))
        .route("/api/users/me/password", put(users_me::change_password))
        .route("/api/users/me/email", put(users_me::change_email))
        .route("/api/users/me/username", put(users_me::change_username))
        .route("/api/users/me/profile", patch(users_me::update_profile))
        .route("/api/users/me/identities", get(users_me::list_identities))
        .route(
            "/api/users/me/identities/{provider}",
            delete(users_me::unbind_identity),
        )
        .route("/api/users/me/sessions", get(users_me::list_sessions))
        .route(
            "/api/users/me/sessions/{id}",
            delete(users_me::revoke_session),
        )
        .route("/api/auth/account/delete", post(account::request_deletion))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    let admin_routes = Router::new()
        .route("/api/admin/users", get(admin::list_users))
        .route("/api/admin/users/{id}", get(admin::user_detail))
        .route("/api/admin/users/{id}/ban", put(admin::set_ban))
        .route(
            "/api/admin/users/{id}/force-logout",
            post(admin::force_logout),
        )
        .route("/api/admin/stats", get(admin::stats))
        .route("/api/admin/logs", get(admin_logs::list_logs))
        .route("/api/admin/logs/stream", get(admin_logs::stream_logs))
        .route("/api/admin/metrics/history", get(metrics_admin::history))
        .route("/api/admin/metrics/live", get(metrics_admin::stream_live))
        .route("/api/admin/db/tables", get(db::list_tables))
        .route(
            "/api/admin/db/tables/{table}",
            get(db::browse).post(db::insert_row),
        )
        .route(
            "/api/admin/db/tables/{table}/{id}",
            axum::routing::put(db::update_row).delete(db::delete_row),
        )
        .route(
            "/api/admin/config",
            get(config::get_config).put(config::update_config),
        )
        .route("/api/admin/config/restart", post(config::restart_container))
        .route("/api/admin/jobs", get(jobs::list_jobs))
        .route(
            "/api/admin/jobs/{name}/enabled",
            put(jobs::set_enabled),
        )
        .route(
            "/api/admin/jobs/{name}/interval",
            put(jobs::set_interval),
        )
        .route("/api/admin/jobs/{name}/param", put(jobs::set_param))
        .route("/api/admin/jobs/{name}/run", post(jobs::run_now))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_admin,
        ));

    Router::new()
        .route("/health", get(health::handler))
        .route("/metrics", get(metrics::handler))
        // admin SPA（rust-embed；未构建 dist 时 503）
        .route("/admin", get(admin_web::admin_root))
        .route("/admin/", get(admin_web::admin_index))
        .route("/admin/{*path}", get(admin_web::admin_spa))
        .route("/api/users/register", post(users::register))
        .route("/api/users/login", post(users::login))
        .route("/api/auth/signup/request", post(signup::request_signup))
        .route("/api/auth/signup/confirm-code", post(signup::confirm_code))
        .route(
            "/api/auth/signup/confirm",
            get(signup::confirm_form).post(signup::confirm_submit),
        )
        .route("/api/auth/refresh", post(session::refresh))
        .route("/api/auth/logout", post(session::logout))
        .route(
            "/api/auth/verify-email/request",
            post(verify_email::request_verification),
        )
        .route("/api/auth/verify-email/confirm", get(verify_email::confirm))
        .route(
            "/api/auth/email-change/confirm",
            get(verify_email::confirm_email_change),
        )
        .route("/api/auth/oauth/github", get(oauth::github_authorize))
        .route(
            "/api/auth/oauth/github/callback",
            get(oauth::github_callback),
        )
        .route("/api/auth/oauth/google", get(oauth::google_authorize))
        .route(
            "/api/auth/oauth/google/callback",
            get(oauth::google_callback),
        )
        .route("/api/auth/magic-link", post(magic::request_magic_link))
        .route("/api/auth/magic-link/verify", get(magic::verify_magic_link))
        .route("/api/auth/email-entry", post(email_entry::request_entry))
        .route(
            "/api/auth/email-entry/confirm",
            post(email_entry::confirm_entry),
        )
        .route(
            "/api/auth/password-reset/request",
            post(password_reset::request_reset),
        )
        .route(
            "/api/auth/password-reset/confirm-code",
            post(password_reset::confirm_code),
        )
        .route(
            "/api/auth/password-reset/confirm",
            get(password_reset::confirm_form).post(password_reset::confirm_submit),
        )
        .route("/api/auth/account/recover", post(account::request_recovery))
        .route(
            "/api/auth/account/confirm-deletion",
            get(account::confirm_deletion),
        )
        .route(
            "/api/auth/account/confirm-recovery",
            get(account::confirm_recovery),
        )
        .merge(protected)
        .merge(admin_routes)
        .with_state(state)
}
