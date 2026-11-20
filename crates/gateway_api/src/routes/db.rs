//! 管理端数据库浏览：只读查看各表内容。
//!
//! 网关层只做参数解析与 DTO 映射；表白名单、排序校验、敏感列打码
//! 全在业务层（rovortex_users::db_browse），SQL 在 storage_pg::PgDbBrowser。
//! 路由仅 require_admin 中间件之后可达。

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::error::ApiError;
use crate::routes::auth::AdminUser;
use crate::state::AppState;
use rovortex_users::audit::{AuditAction, NewAuditLog};
use rovortex_users::db_browse::{
    BrowseParams, DbBrowseError, default_sort, resolve_sort_column, resolve_table,
    resolve_writable_columns,
};

#[derive(Debug, Serialize)]
pub struct TableInfo {
    pub name: String,
    pub rows: i64,
}

/// GET /api/admin/db/tables —— 白名单表清单 + 行数。
pub async fn list_tables(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<TableInfo>>, ApiError> {
    let tables = state
        .db_browser
        .list_tables()
        .await
        .map_err(db_error)?
        .into_iter()
        .map(|t| TableInfo { name: t.name, rows: t.rows })
        .collect();
    Ok(Json(tables))
}

#[derive(Debug, Serialize)]
pub struct ColumnInfo {
    pub name: String,
    pub data_type: String,
}

#[derive(Debug, Serialize)]
pub struct BrowseResponse {
    pub table: String,
    pub columns: Vec<ColumnInfo>,
    /// 每行是完整列的 JSON 对象（原样，不打码）。
    pub rows: Vec<Value>,
    pub total: i64,
    pub page: u32,
    pub per_page: u32,
}

#[derive(Debug, Deserialize)]
pub struct BrowseQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    /// 排序列名；必须在表的白名单列内（防注入）。
    pub sort: Option<String>,
    /// "asc"（默认）| "desc"。
    pub order: Option<String>,
    /// 全字段模糊搜索（ILIKE %q%），空串或 None 不过滤。
    pub q: Option<String>,
}

/// GET /api/admin/db/tables/{table}?page=&per_page=&sort=&order=&q= —— 分页浏览表内容。
pub async fn browse(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(table): Path<String>,
    Query(query): Query<BrowseQuery>,
) -> Result<Json<BrowseResponse>, ApiError> {
    let table = resolve_table(&table).map_err(db_error)?;
    let per_page = query.per_page.unwrap_or(20).clamp(1, 200);
    let page = query.page.unwrap_or(1).max(1);
    let limit = per_page as i64;
    let offset = ((page - 1) as i64) * limit;

    let columns = state.db_browser.describe(table).await.map_err(db_error)?;
    let (sort, descending) = match query.sort.as_deref() {
        Some(s) => {
            let col = resolve_sort_column(s, &columns).map_err(db_error)?;
            (col, query.order.as_deref() == Some("desc"))
        }
        None => default_sort(&columns),
    };
    let search = query.q.as_deref().unwrap_or("").trim().to_string();

    let params = BrowseParams {
        table: table.to_string(),
        limit,
        offset,
        sort: Some(sort),
        descending,
        search,
    };
    let raw_rows = state
        .db_browser
        .browse_rows(&params)
        .await
        .map_err(db_error)?;
    let total = state
        .db_browser
        .count_rows(table, &params.search)
        .await
        .map_err(db_error)?;

    Ok(Json(BrowseResponse {
        table: table.to_string(),
        columns: columns
            .into_iter()
            .map(|c| ColumnInfo { name: c.name, data_type: c.data_type })
            .collect(),
        rows: raw_rows,
        total,
        page,
        per_page,
    }))
}

/// DbBrowseError → HTTP 错误映射（网关层唯一的边界翻译点）。
fn db_error(e: DbBrowseError) -> ApiError {
    match e {
        DbBrowseError::UnknownTable(t) => ApiError::bad_request(format!("unknown table: {t}")),
        DbBrowseError::UnknownColumn(c) => ApiError::bad_request(format!("unknown column: {c}")),
        DbBrowseError::ReadOnly(t) => ApiError::bad_request(format!("table is read-only: {t}")),
        DbBrowseError::RowNotFound => ApiError::not_found(),
        DbBrowseError::Database(m) => ApiError::internal(m),
    }
}

// ---- 行级写操作（insert / update / delete，全部写审计） ----

#[derive(Debug, Deserialize)]
pub struct RowPayload {
    /// 列名 → 值。列名在 WRITABLE_COLUMNS 白名单内才接受。
    pub columns: std::collections::HashMap<String, Value>,
}

/// 写操作审计（失败不阻断业务，与其他审计点一致）。
async fn audit_write(
    state: &AppState,
    admin: &AdminUser,
    action: AuditAction,
    table: &str,
    detail: String,
) {
    if let Err(e) = state
        .audit
        .append(NewAuditLog {
            user_id: Some(admin.user_id),
            action,
            detail: format!("{table}: {detail}"),
            client_ip: String::new(),
        })
        .await
    {
        tracing::warn!(error = %e, "failed to append db-write audit log");
    }
}

/// POST /api/admin/db/tables/{table} —— 插入一行。
pub async fn insert_row(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(table): Path<String>,
    Json(payload): Json<RowPayload>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let table = resolve_table(&table).map_err(db_error)?;
    let mut columns: Vec<(String, Value)> = payload.columns.into_iter().collect();
    columns.sort_by(|a, b| a.0.cmp(&b.0));
    resolve_writable_columns(table, &columns).map_err(db_error)?;
    let id = state
        .db_browser
        .insert_row(table, &columns)
        .await
        .map_err(db_error)?;
    audit_write(
        &state,
        &admin,
        AuditAction::AdminDbInsert,
        table,
        format!("id={id} cols={}", columns.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(",")),
    )
    .await;
    Ok(Json(serde_json::json!({ "id": id })))
}

/// PUT /api/admin/db/tables/{table}/{id} —— 按 id 更新一行。
pub async fn update_row(
    State(state): State<AppState>,
    admin: AdminUser,
    Path((table, id)): Path<(String, Uuid)>,
    Json(payload): Json<RowPayload>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let table = resolve_table(&table).map_err(db_error)?;
    let mut columns: Vec<(String, Value)> = payload.columns.into_iter().collect();
    columns.sort_by(|a, b| a.0.cmp(&b.0));
    if columns.is_empty() {
        return Err(ApiError::bad_request("no columns to update".into()));
    }
    resolve_writable_columns(table, &columns).map_err(db_error)?;
    let affected = state
        .db_browser
        .update_row(table, id, &columns)
        .await
        .map_err(db_error)?;
    if affected == 0 {
        return Err(ApiError::not_found());
    }
    audit_write(
        &state,
        &admin,
        AuditAction::AdminDbUpdate,
        table,
        format!("id={id} cols={}", columns.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(",")),
    )
    .await;
    Ok(Json(serde_json::json!({ "updated": affected })))
}

/// DELETE /api/admin/db/tables/{table}/{id} —— 按 id 删除一行。
pub async fn delete_row(
    State(state): State<AppState>,
    admin: AdminUser,
    Path((table, id)): Path<(String, Uuid)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let table = resolve_table(&table).map_err(db_error)?;
    let affected = state
        .db_browser
        .delete_row(table, id)
        .await
        .map_err(db_error)?;
    if affected == 0 {
        return Err(ApiError::not_found());
    }
    audit_write(&state, &admin, AuditAction::AdminDbDelete, table, format!("id={id}")).await;
    Ok(Json(serde_json::json!({ "deleted": affected })))
}
