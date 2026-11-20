//! 管理端数据库浏览（读 + 行级增删改）—— 业务层契约与领域规则。
//!
//! 这里只定义：允许浏览哪些表、哪些列可写；具体查询由持久化层实现
//! （storage_pg::PgDbBrowser）。网关层只做参数解析与 DTO 映射，不接触 SQL。
//! 管理端是信任边界内的运维工具：列值原样展示（不打码），全列可编辑。

use serde_json::Value;
use uuid::Uuid;

/// 允许浏览的表白名单（不含 _sqlx_migrations 等内部表）。
pub const BROWSABLE_TABLES: &[&str] = &[
    "users",
    "refresh_tokens",
    "email_verifications",
    "audit_logs",
    "user_identities",
];

/// 不可写列：GENERATED ALWAYS 列（PG 拒绝直接写）。其余全部列均可增改。
const NON_WRITABLE_COLUMNS: &[(&str, &[&str])] = &[(
    "users",
    &["username_key", "email_key"], // GENERATED ALWAYS AS lower(...)
)];

#[derive(Debug, thiserror::Error)]
pub enum DbBrowseError {
    #[error("unknown table: {0}")]
    UnknownTable(String),
    #[error("unknown column: {0}")]
    UnknownColumn(String),
    #[error("column is not writable: {0}")]
    ReadOnly(String),
    #[error("row not found")]
    RowNotFound,
    #[error("database error: {0}")]
    Database(String),
}

impl DbBrowseError {
    pub fn database(e: impl std::fmt::Display) -> Self {
        Self::Database(e.to_string())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ColumnInfo {
    pub name: String,
    pub data_type: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TableSummary {
    pub name: String,
    pub rows: i64,
}

/// 浏览查询参数（已由网关层解析为强类型）。
#[derive(Debug, Clone)]
pub struct BrowseParams {
    /// 已通过白名单校验的表名。
    pub table: String,
    pub limit: i64,
    pub offset: i64,
    /// None = 默认排序（created_at DESC，无则 id ASC）。
    pub sort: Option<String>,
    pub descending: bool,
    /// 空串 = 不过滤；否则全字段 ILIKE。
    pub search: String,
}

#[async_trait::async_trait]
pub trait DbBrowser: Send + Sync {
    /// 白名单内各表的行数。
    async fn list_tables(&self) -> Result<Vec<TableSummary>, DbBrowseError>;
    /// 表的列信息（information_schema，ordinal_position 序）。
    async fn describe(&self, table: &str) -> Result<Vec<ColumnInfo>, DbBrowseError>;
    /// 分页浏览：返回完整行的 JSON 对象数组（原样，不打码）。
    async fn browse_rows(&self, params: &BrowseParams) -> Result<Vec<Value>, DbBrowseError>;
    /// 与 browse_rows 同过滤条件下的行数。
    async fn count_rows(&self, table: &str, search: &str) -> Result<i64, DbBrowseError>;
    /// 插入一行：列须属于该表且非 GENERATED。返回新行 id。
    async fn insert_row(
        &self,
        table: &str,
        columns: &[(String, Value)],
    ) -> Result<Uuid, DbBrowseError>;
    /// 更新一行（按 UUID 主键 id）：列须属于该表且非 GENERATED。
    async fn update_row(
        &self,
        table: &str,
        id: Uuid,
        columns: &[(String, Value)],
    ) -> Result<u64, DbBrowseError>;
    /// 删除一行（按 UUID 主键 id）。
    async fn delete_row(&self, table: &str, id: Uuid) -> Result<u64, DbBrowseError>;
}

/// 挡掉 GENERATED 列；列是否真属于该表由 storage_pg 的 describe 兜底校验。
pub fn resolve_writable_columns(
    table: &str,
    columns: &[(String, Value)],
) -> Result<(), DbBrowseError> {
    let blocked = NON_WRITABLE_COLUMNS
        .iter()
        .find(|(t, _)| *t == table)
        .map(|(_, cols)| *cols)
        .unwrap_or(&[]);
    for (name, _) in columns {
        if blocked.contains(&name.as_str()) {
            return Err(DbBrowseError::ReadOnly(format!("{table}.{name}")));
        }
    }
    Ok(())
}

/// 校验表名在白名单内。
pub fn resolve_table(table: &str) -> Result<&'static str, DbBrowseError> {
    BROWSABLE_TABLES
        .iter()
        .copied()
        .find(|t| *t == table)
        .ok_or_else(|| DbBrowseError::UnknownTable(table.to_string()))
}

/// 校验排序列确实属于这张表，杜绝 ORDER BY 注入（标识符不能走绑定参数）。
pub fn resolve_sort_column(sort: &str, valid: &[ColumnInfo]) -> Result<String, DbBrowseError> {
    valid
        .iter()
        .find(|c| c.name == sort)
        .map(|c| c.name.clone())
        .ok_or_else(|| DbBrowseError::UnknownColumn(sort.to_string()))
}

/// 默认排序：created_at DESC；没有该列（本项目表都有，防御性回退）则 id ASC。
pub fn default_sort(columns: &[ColumnInfo]) -> (String, bool) {
    match columns.iter().find(|c| c.name == "created_at") {
        Some(c) => (c.name.clone(), true),
        None => ("id".to_string(), false),
    }
}
