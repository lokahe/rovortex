//! 管理端定时任务：列表 / 开关 / 立即运行。
//!
//! 任务 SQL 模板编译期写死（jobs::registry），本层只暴露操作与状态。
//! 开关与 interval 的变更写 app_settings（持久化）+ 内存 handle（立即生效）。

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;

use crate::error::ApiError;
use crate::jobs::{JobCtx, JobHandle, LastRun};
use crate::routes::auth::AdminUser;
use crate::state::AppState;
use rovortex_users::audit::{AuditAction, NewAuditLog};

#[derive(Debug, serde::Serialize)]
pub struct JobView {
    pub name: &'static str,
    pub doc: &'static str,
    /// 当前生效间隔（秒）。
    pub interval_secs: u64,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run: Option<LastRun>,
}

fn to_view_sync(h: &JobHandle) -> JobView {
    JobView {
        name: h.name(),
        doc: h.doc(),
        interval_secs: 0,
        enabled: h.is_enabled(),
        last_run: None,
    }
}

/// GET /api/admin/jobs —— 全部任务 + 运行状态。
pub async fn list_jobs(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<JobView>>, ApiError> {
    let mut views = Vec::new();
    for h in state.jobs.iter() {
        views.push(JobView {
            interval_secs: h.interval_secs().await,
            last_run: h.last_run().await,
            ..to_view_sync(h)
        });
    }
    Ok(Json(views))
}

#[derive(Debug, Deserialize)]
pub struct ToggleRequest {
    pub enabled: bool,
}

fn find_job(state: &AppState, name: &str) -> Result<Arc<JobHandle>, ApiError> {
    state
        .jobs
        .iter()
        .find(|h| h.name() == name)
        .cloned()
        .ok_or_else(|| ApiError::not_found_with(format!("unknown job: {name}")))
}

/// PUT /api/admin/jobs/{name}/enabled —— 暂停/恢复（写 app_settings 持久化）。
pub async fn set_enabled(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(name): Path<String>,
    Json(req): Json<ToggleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let job = find_job(&state, &name)?;
    let key = format!("job.{name}.enabled");
    state
        .settings
        .set(&key, if req.enabled { "1" } else { "0" })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    job.set_enabled(req.enabled);
    let _ = state
        .audit
        .append(NewAuditLog {
            user_id: Some(admin.user_id),
            action: AuditAction::AdminJobToggle,
            detail: format!("job={name} enabled={}", req.enabled),
            client_ip: String::new(),
        })
        .await;
    Ok(Json(serde_json::json!({ "name": name, "enabled": req.enabled })))
}

#[derive(Debug, Deserialize)]
pub struct IntervalRequest {
    /// 新间隔（秒）；下限 60。
    pub interval_secs: u64,
}

/// PUT /api/admin/jobs/{name}/interval —— 改频率（写 app_settings 持久化）。
pub async fn set_interval(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(name): Path<String>,
    Json(req): Json<IntervalRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let job = find_job(&state, &name)?;
    let secs = req.interval_secs.max(60);
    let key = format!("job.{name}.interval_secs");
    state
        .settings
        .set(&key, &secs.to_string())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    job.set_interval_secs(secs).await;
    let _ = state
        .audit
        .append(NewAuditLog {
            user_id: Some(admin.user_id),
            action: AuditAction::AdminJobToggle,
            detail: format!("job={name} interval_secs={secs}"),
            client_ip: String::new(),
        })
        .await;
    Ok(Json(serde_json::json!({ "name": name, "interval_secs": secs })))
}

/// POST /api/admin/jobs/{name}/run —— 立即执行一次。
pub async fn run_now(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(name): Path<String>,
) -> Result<Json<LastRun>, ApiError> {
    let job = find_job(&state, &name)?;
    let ctx = JobCtx {
        users: state.users.clone(),
        settings: state.settings.clone(),
        audit: state.audit.clone(),
    };
    let run = job.run_once(ctx).await;
    let _ = state
        .audit
        .append(NewAuditLog {
            user_id: Some(admin.user_id),
            action: AuditAction::AdminJobRun,
            detail: format!(
                "job={name} ok={} elapsed_ms={}",
                run.err.is_none(),
                run.elapsed_ms
            ),
            client_ip: String::new(),
        })
        .await;
    Ok(Json(run))
}

/// PUT 之外的错误补充（ApiError 目前没有带消息的 not_found）。
impl ApiError {
    pub fn not_found_with(message: String) -> Self {
        Self::Http(
            axum::http::StatusCode::NOT_FOUND,
            "not_found",
            message,
        )
    }
}
