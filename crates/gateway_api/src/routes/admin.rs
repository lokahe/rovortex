//! 管理接口：`/api/admin/*`，全部挂 require_admin 中间件。
//!
//! 唯一授权依据是 users.is_admin（每请求实时查库，撤销立即生效）。
//! 首个 admin 由 ROVORTEX_ADMIN_EMAILS 在组合根启动时提升。

use axum::Json;
use axum::extract::{Path, Query, State};
use chrono::{DateTime, Utc};
use rovortex_users::UserError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::routes::auth::AdminUser;
use crate::state::AppState;

/// users.status 的封禁语义（业务层 BANNED_STATUS 的镜像；0001 建表 SMALLINT）。
const STATUS_BANNED: i16 = rovortex_users::BANNED_STATUS;
const STATUS_ACTIVE: i16 = 0;

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
        banned: u.status == rovortex_users::BANNED_STATUS,
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

    let repo = state.users.repository();
    let users = repo
        .list_users(query.q.as_deref(), per_page as i64, offset)
        .await?;
    let total = repo.count_users(query.q.as_deref()).await?;

    Ok(Json(ListUsersResponse {
        users: users.into_iter().map(to_view).collect(),
        total,
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
    let repo = state.users.repository();
    let user = repo
        .find_by_id(user_id)
        .await?
        .ok_or(ApiError::not_found())?;

    let identities = state.users.identities().list_for_user(user_id).await?;
    let audit_logs = state.users.audit_logs_for_user(user_id, 20).await?;

    Ok(Json(AdminUserDetail {
        user: to_view(user),
        identities: identities
            .into_iter()
            .map(|i| IdentityView {
                provider: i.provider,
                provider_uid: i.provider_uid,
                email: i.email,
                created_at: i.created_at,
            })
            .collect(),
        audit_logs: audit_logs
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
/// 封禁时同时吊销全部会话（已登录设备立即失效）。
pub async fn set_ban(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(user_id): Path<Uuid>,
    Json(req): Json<BanRequest>,
) -> Result<axum::http::StatusCode, ApiError> {
    if user_id == admin.user_id {
        return Err(ApiError::bad_request("cannot ban yourself".into()));
    }
    let status = if req.banned { STATUS_BANNED } else { STATUS_ACTIVE };
    state
        .users
        .repository()
        .set_status(user_id, status)
        .await?;
    if req.banned {
        state.users.revoke_sessions_for(user_id).await?;
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
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
    let repo = state.users.repository();
    let total_users = repo.count_users(None).await?;
    let events = repo.count_audit_by_action(since).await?;
    Ok(Json(StatsResponse {
        since,
        total_users,
        events,
    }))
}
