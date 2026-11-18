//! 管理端数据库浏览：只读查看各表内容。
//!
//! 安全边界：表名走编译期白名单（拦截注入）；敏感列（哈希/凭据）在
//! 返回前打码；仅 require_admin 中间件之后的路由可达。

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::postgres::PgRow;
use sqlx::Row;

use crate::error::ApiError;
use crate::routes::auth::AdminUser;
use crate::state::AppState;

/// 允许浏览的表白名单（不含 _sqlx_migrations 等内部表）。
const TABLES: &[&str] = &[
    "users",
    "refresh_tokens",
    "email_verifications",
    "audit_logs",
    "user_identities",
];

/// 值打码的敏感列：只暴露前 8 位 + 长度，足以比对、不足以冒用。
const MASKED_COLUMNS: &[&str] = &["password_hash", "token_hash"];

fn resolve_table(table: &str) -> Result<&'static str, ApiError> {
    TABLES
        .iter()
        .copied()
        .find(|t| *t == table)
        .ok_or_else(|| ApiError::bad_request(format!("unknown table: {table}")))
}

#[derive(Debug, Serialize)]
pub struct TableInfo {
    pub name: &'static str,
    pub rows: i64,
}

/// GET /api/admin/db/tables —— 白名单表清单 + 行数。
pub async fn list_tables(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<TableInfo>>, ApiError> {
    let mut tables = Vec::with_capacity(TABLES.len());
    for name in TABLES {
        let rows: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {name}"))
            .fetch_one(&state.db)
            .await
            .map_err(|e| ApiError::internal(format!("count {name} failed: {e}")))?;
        tables.push(TableInfo { name, rows });
    }
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
    /// 每行是完整列的 JSON 对象（敏感列已打码）。
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

/// 校验排序列确实属于这张表，杜绝 ORDER BY 注入。
fn resolve_sort_column(sort: &str, valid: &[ColumnInfo]) -> Result<String, ApiError> {
    valid
        .iter()
        .find(|c| c.name == sort)
        .map(|c| c.name.clone())
        .ok_or_else(|| ApiError::bad_request(format!("unknown column: {sort}")))
}

/// GET /api/admin/db/tables/{table}?page=&per_page=&sort=&order=&q= —— 分页浏览表内容。
pub async fn browse(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(table): Path<String>,
    Query(query): Query<BrowseQuery>,
) -> Result<Json<BrowseResponse>, ApiError> {
    let table = resolve_table(&table)?;
    let per_page = query.per_page.unwrap_or(20).clamp(1, 200);
    let page = query.page.unwrap_or(1).max(1);
    let limit = per_page as i64;
    let offset = ((page - 1) as i64) * limit;

    let columns: Vec<ColumnInfo> = sqlx::query(
        r#"SELECT column_name, data_type FROM information_schema.columns
           WHERE table_schema = 'public' AND table_name = $1
           ORDER BY ordinal_position"#,
    )
    .bind(table)
    .map(|row: PgRow| ColumnInfo {
        name: row.get("column_name"),
        data_type: row.get("data_type"),
    })
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::internal(format!("describe {table} failed: {e}")))?;

    // 排序：默认 created_at DESC；显式指定时校验列名后拼接（标识符不能走绑定参数）。
    let (sort_col, order_sql) = match query.sort.as_deref() {
        Some(s) => {
            let col = resolve_sort_column(s, &columns)?;
            let dir = match query.order.as_deref() {
                Some("desc") => "DESC",
                _ => "ASC",
            };
            (col, dir)
        }
        // 无指定时回退到 created_at DESC；没有该列（不存在于本项目表）则 id ASC。
        None => {
            let col = columns
                .iter()
                .find(|c| c.name == "created_at")
                .map(|c| c.name.clone())
                .unwrap_or_else(|| "id".to_string());
            (col, "DESC")
        }
    };

    let search = query.q.as_deref().unwrap_or("").trim().to_string();

    // to_jsonb 一行打成对象，免为每张表写一份 row 映射。
    // sort_col/where_clause 已过白名单或为固定片段，非用户原文。
    // 占位符按有无 WHERE 分支生成：搜索时 $1=q/$2=limit/$3=offset，否则 $1=limit/$2=offset。
    let raw_rows: Vec<Value> = if search.is_empty() {
        let sql = format!(
            r#"SELECT to_jsonb(t) AS row FROM {table} t ORDER BY {sort_col} {order_sql} LIMIT $1 OFFSET $2"#
        );
        sqlx::query(&sql)
            .bind(limit)
            .bind(offset)
            .map(|row: PgRow| row.get::<Value, _>("row"))
            .fetch_all(&state.db)
            .await
            .map_err(|e| ApiError::internal(format!("browse {table} failed: {e}")))?
    } else {
        let sql = format!(
            r#"SELECT to_jsonb(t) AS row FROM {table} t WHERE t::text ILIKE '%' || $1 || '%' ORDER BY {sort_col} {order_sql} LIMIT $2 OFFSET $3"#
        );
        sqlx::query(&sql)
            .bind(&search)
            .bind(limit)
            .bind(offset)
            .map(|row: PgRow| row.get::<Value, _>("row"))
            .fetch_all(&state.db)
            .await
            .map_err(|e| ApiError::internal(format!("browse {table} failed: {e}")))?
    };

    let filtered_total: i64 = if search.is_empty() {
        sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&state.db)
            .await
            .map_err(|e| ApiError::internal(format!("count {table} failed: {e}")))?
    } else {
        sqlx::query_scalar(&format!(
            r#"SELECT COUNT(*) FROM {table} t WHERE t::text ILIKE '%' || $1 || '%'"#
        ))
        .bind(&search)
        .fetch_one(&state.db)
        .await
        .map_err(|e| ApiError::internal(format!("count {table} failed: {e}")))?
    };

    Ok(Json(BrowseResponse {
        table: table.to_string(),
        columns,
        rows: mask_rows(raw_rows),
        total: filtered_total,
        page,
        per_page,
    }))
}

fn mask_rows(rows: Vec<Value>) -> Vec<Value> {
    rows.into_iter()
        .map(|mut row| {
            if let Some(obj) = row.as_object_mut() {
                for col in MASKED_COLUMNS {
                    if let Some(v) = obj.get_mut(*col) {
                        if let Some(s) = v.as_str() {
                            let prefix: String = s.chars().take(8).collect();
                            *v = json!(format!("{prefix}…(len {})", s.len()));
                        }
                    }
                }
            }
            row
        })
        .collect()
}
