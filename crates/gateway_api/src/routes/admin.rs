//! 管理接口：`/api/admin/*`，全部挂 require_admin 中间件。
//!
//! 唯一授权依据是 users.is_admin（每请求实时查库，撤销立即生效）。
//! 首个 admin 由 ROVORTEX_ADMIN_EMAILS 在组合根启动时提升（AdminService）。
//! 业务编排（列表/详情聚合/封禁+吊销会话/统计）在业务层 AdminService，
//! 本文件只做参数解析与 DTO 映射。

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::routes::auth::AdminUser;
use crate::state::AppState;
use rovortex_users::admin::BANNED_STATUS;

#[derive(Debug, Serialize)]
pub struct AdminUserView {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub is_admin: bool,
    pub banned: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn to_view(u: rovortex_users::User) -> AdminUserView {
    AdminUserView {
        id: u.id,
        username: u.username,
        email: u.email,
        email_verified: u.email_verified,
        is_admin: u.is_admin,
        banned: u.status == BANNED_STATUS,
        created_at: u.created_at,
        updated_at: u.updated_at,
    }
}

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub q: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct ListUsersResponse {
    pub users: Vec<AdminUserView>,
    pub total: i64,
    pub page: u32,
    pub per_page: u32,
}

/// GET /api/admin/users?q=&page=&per_page= —— 分页用户列表。
pub async fn list_users(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<ListUsersResponse>, ApiError> {
    let per_page = query.per_page.unwrap_or(20).clamp(1, 100);
    let page = query.page.unwrap_or(1).max(1);
    let offset = ((page - 1) as i64) * (per_page as i64);

    let result = state
        .admin
        .list_users(query.q.as_deref(), per_page as i64, offset)
        .await?;

    Ok(Json(ListUsersResponse {
        users: result.users.into_iter().map(to_view).collect(),
        total: result.total,
        page,
        per_page,
    }))
}

#[derive(Debug, Serialize)]
pub struct AdminUserDetail {
    #[serde(flatten)]
    pub user: AdminUserView,
    /// 绑定的外部身份（github / magic 等）。
    pub identities: Vec<IdentityView>,
    /// 最近 20 条审计记录。
    pub audit_logs: Vec<AuditEntryView>,
}

#[derive(Debug, Serialize)]
pub struct IdentityView {
    pub provider: String,
    pub provider_uid: String,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct AuditEntryView {
    pub action: String,
    pub detail: String,
    pub client_ip: String,
    pub created_at: DateTime<Utc>,
}

/// GET /api/admin/users/:id —— 单用户详情（含身份绑定 + 审计）。
pub async fn user_detail(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<AdminUserDetail>, ApiError> {
    let detail = state
        .admin
        .user_detail(user_id, 20)
        .await
        .map_err(|_| ApiError::not_found())?;

    Ok(Json(AdminUserDetail {
        user: to_view(detail.user),
        identities: detail
            .identities
            .into_iter()
            .map(|i| IdentityView {
                provider: i.provider,
                provider_uid: i.provider_uid,
                email: i.email,
                created_at: i.created_at,
            })
            .collect(),
        audit_logs: detail
            .audit_logs
            .into_iter()
            .map(|a| AuditEntryView {
                action: a.action,
                detail: a.detail,
                client_ip: a.client_ip,
                created_at: a.created_at,
            })
            .collect(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct BanRequest {
    pub banned: bool,
}

/// PUT /api/admin/users/:id/ban —— 封禁 / 解封。
/// 封禁时同时吊销全部会话（已登录设备立即失效）——原子用例在 AdminService。
pub async fn set_ban(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(user_id): Path<Uuid>,
    Json(req): Json<BanRequest>,
) -> Result<axum::http::StatusCode, ApiError> {
    if user_id == admin.user_id {
        return Err(ApiError::bad_request("cannot ban yourself".into()));
    }
    state.admin.set_ban(user_id, req.banned).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
pub struct ForceLogoutResponse {
    pub revoked: u64,
}

/// POST /api/admin/users/:id/force-logout —— 强制下线（吊销全部会话）。
pub async fn force_logout(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<ForceLogoutResponse>, ApiError> {
    if user_id == admin.user_id {
        return Err(ApiError::bad_request("cannot force-logout yourself".into()));
    }
    let revoked = state
        .admin
        .revoke_user_sessions(admin.user_id, user_id)
        .await
        .map_err(|_| ApiError::not_found())?;
    Ok(Json(ForceLogoutResponse { revoked }))
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    /// 时间窗口起点（now - 7 天）。
    pub since: DateTime<Utc>,
    /// 用户总数。
    pub total_users: i64,
    /// 各审计动作 7 天内计数，如 register / login_success。
    pub events: Vec<(String, i64)>,
}

/// GET /api/admin/stats —— 仪表盘统计（7 天审计事件 + 用户总数）。
pub async fn stats(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<StatsResponse>, ApiError> {
    let since = Utc::now() - chrono::Duration::days(7);
    let result = state.admin.stats(since).await?;
    Ok(Json(StatsResponse {
        since: result.since,
        total_users: result.total_users,
        events: result.events,
    }))
}
