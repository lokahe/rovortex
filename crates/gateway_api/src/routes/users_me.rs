//! 受保护的用户接口：要求有效的 Bearer token。

use axum::Json;
use axum::http::StatusCode;
use axum::extract::{ConnectInfo, Path, State};
use std::net::SocketAddr;
use chrono::{DateTime, Utc};
use rovortex_users::{ProfilePatch, UserError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::routes::auth::AuthUser;
use crate::routes::users::client_ip;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct MeResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub website_url: Option<String>,
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

#[derive(Debug, Deserialize)]
pub struct ChangeUsernameRequest {
    pub new_username: String,
}

/// PATCH 语义的资料更新：字段缺省 = 不动；null = 清空。
///
/// serde 默认会把 `"bio": null` 反序列化成外层 `None`（与缺省无法区分），
/// 这里用 double_option：缺省 → None，present(null) → Some(None)，present(v) → Some(Some(v))。
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    #[serde(default, deserialize_with = "double_option")]
    pub display_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub avatar_url: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub bio: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub website_url: Option<Option<String>>,
}

fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(de).map(Some)
}

#[derive(Debug, Serialize)]
pub struct IdentityResponse {
    pub provider: String,
    pub email: Option<String>,
    pub has_raw_profile: bool,
    pub created_at: DateTime<Utc>,
}

fn me_response(u: rovortex_users::User) -> MeResponse {
    MeResponse {
        id: u.id,
        username: u.username,
        email: u.email,
        email_verified: u.email_verified,
        display_name: u.display_name,
        avatar_url: u.avatar_url,
        bio: u.bio,
        website_url: u.website_url,
        created_at: u.created_at,
        updated_at: u.updated_at,
    }
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
    Ok(Json(me_response(user)))
}

/// PUT /api/users/me/password —— 204 No Content（成功后全部会话失效）
pub async fn change_password(
    State(state): State<AppState>,
    auth: AuthUser,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<axum::http::StatusCode, ApiError> {
    let ip = client_ip(&headers, addr);
    state
        .users
        .change_password(auth.user_id, &req.old_password, &req.new_password, &ip)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// PUT /api/users/me/email —— 202 Accepted（确认链接发到新邮箱，防枚举恒 202）
pub async fn change_email(
    State(state): State<AppState>,
    auth: AuthUser,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ChangeEmailRequest>,
) -> Result<axum::http::StatusCode, ApiError> {
    let ip = client_ip(&headers, addr);
    state
        .users
        .request_email_change(auth.user_id, &req.new_email, &ip)
        .await?;
    Ok(axum::http::StatusCode::ACCEPTED)
}

/// PUT /api/users/me/username —— 200 OK（返回更新后的资料）
pub async fn change_username(
    State(state): State<AppState>,
    auth: AuthUser,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ChangeUsernameRequest>,
) -> Result<Json<MeResponse>, ApiError> {
    let ip = client_ip(&headers, addr);
    state
        .users
        .change_username(auth.user_id, &req.new_username, &ip)
        .await?;
    let user = state
        .users
        .repository()
        .find_by_id(auth.user_id)
        .await?
        .ok_or(UserError::UserNotFound)?;
    Ok(Json(me_response(user)))
}

/// PATCH /api/users/me/profile —— 200 OK（部分更新展示资料）
pub async fn update_profile(
    State(state): State<AppState>,
    auth: AuthUser,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Json<MeResponse>, ApiError> {
    let ip = client_ip(&headers, addr);
    let patch = ProfilePatch {
        display_name: req.display_name,
        avatar_url: req.avatar_url,
        bio: req.bio,
        website_url: req.website_url,
    };
    let user = state
        .users
        .update_profile(auth.user_id, patch, &ip)
        .await?;
    Ok(Json(me_response(user)))
}

/// GET /api/users/me/identities —— 200 OK（已绑定平台列表）
pub async fn list_identities(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<IdentityResponse>>, ApiError> {
    let identities = state.users.list_identities(auth.user_id).await?;
    Ok(Json(
        identities
            .into_iter()
            .map(|i| IdentityResponse {
                provider: i.provider,
                email: i.email,
                has_raw_profile: i.raw_profile.is_some(),
                created_at: i.created_at,
            })
            .collect(),
    ))
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: Uuid,
    pub device_label: Option<String>,
    pub ua: Option<String>,
    pub ip: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// GET /api/users/me/sessions —— 200 OK（有效会话/设备列表，倒序）
pub async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let sessions = state.users.list_sessions(auth.user_id).await?;
    Ok(Json(
        sessions
            .into_iter()
            .map(|s| SessionResponse {
                id: s.id,
                device_label: s.device_label,
                ua: s.ua,
                ip: s.ip,
                created_at: s.created_at,
                expires_at: s.expires_at,
            })
            .collect(),
    ))
}

/// DELETE /api/users/me/sessions/{id} —— 204 No Content（踢掉指定设备）
pub async fn revoke_session(
    State(state): State<AppState>,
    auth: AuthUser,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let ip = client_ip(&headers, addr);
    state
        .users
        .revoke_session(auth.user_id, session_id, &ip)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /api/users/me/identities/{provider} —— 204 No Content（解绑）
pub async fn unbind_identity(
    State(state): State<AppState>,
    auth: AuthUser,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Path(provider): Path<String>,
) -> Result<axum::http::StatusCode, ApiError> {
    let ip = client_ip(&headers, addr);
    state
        .users
        .unbind_identity(auth.user_id, &provider, &ip)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
