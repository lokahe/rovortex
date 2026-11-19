//! `rovortex_users::DbBrowser` 的 PostgreSQL 实现。
//!
//! 动态表/列标识符来自业务层白名单校验后的值（不能走绑定参数），
//! 值参数照常绑定。占位符按有无 WHERE 分支生成：
//! 搜索时 $1=q/$2=limit/$3=offset，否则 $1=limit/$2=offset。

use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::Row;

use rovortex_users::db_browse::{
    BrowseParams, ColumnInfo, DbBrowseError, DbBrowser, TableSummary, BROWSABLE_TABLES,
};

pub struct PgDbBrowser {
    pool: sqlx::PgPool,
}

impl PgDbBrowser {
    pub fn from_pool(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl DbBrowser for PgDbBrowser {
    async fn list_tables(&self) -> Result<Vec<TableSummary>, DbBrowseError> {
        let mut tables = Vec::with_capacity(BROWSABLE_TABLES.len());
        for name in BROWSABLE_TABLES {
            let rows: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {name}"))
                .fetch_one(&self.pool)
                .await
                .map_err(DbBrowseError::database)?;
            tables.push(TableSummary {
                name: (*name).to_string(),
                rows,
            });
        }
        Ok(tables)
    }

    async fn describe(&self, table: &str) -> Result<Vec<ColumnInfo>, DbBrowseError> {
        sqlx::query(
            r#"SELECT column_name, data_type FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = $1
               ORDER BY ordinal_position"#,
        )
        .bind(table)
        .map(|row: PgRow| ColumnInfo {
            name: row.get("column_name"),
            data_type: row.get("data_type"),
        })
        .fetch_all(&self.pool)
        .await
        .map_err(DbBrowseError::database)
    }

    async fn browse_rows(&self, params: &BrowseParams) -> Result<Vec<Value>, DbBrowseError> {
        let table = &params.table;
        let order_sql = if params.descending { "DESC" } else { "ASC" };
        let sort_col = params.sort.as_deref().unwrap_or("id");

        if params.search.is_empty() {
            let sql = format!(
                r#"SELECT to_jsonb(t) AS row FROM {table} t ORDER BY {sort_col} {order_sql} LIMIT $1 OFFSET $2"#
            );
            sqlx::query(&sql)
                .bind(params.limit)
                .bind(params.offset)
                .map(|row: PgRow| row.get::<Value, _>("row"))
                .fetch_all(&self.pool)
                .await
                .map_err(DbBrowseError::database)
        } else {
            let sql = format!(
                r#"SELECT to_jsonb(t) AS row FROM {table} t WHERE t::text ILIKE '%' || $1 || '%' ORDER BY {sort_col} {order_sql} LIMIT $2 OFFSET $3"#
            );
            sqlx::query(&sql)
                .bind(&params.search)
                .bind(params.limit)
                .bind(params.offset)
                .map(|row: PgRow| row.get::<Value, _>("row"))
                .fetch_all(&self.pool)
                .await
                .map_err(DbBrowseError::database)
        }
    }

    async fn count_rows(&self, table: &str, search: &str) -> Result<i64, DbBrowseError> {
        if search.is_empty() {
            sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
                .fetch_one(&self.pool)
                .await
                .map_err(DbBrowseError::database)
        } else {
            sqlx::query_scalar(&format!(
                r#"SELECT COUNT(*) FROM {table} t WHERE t::text ILIKE '%' || $1 || '%'"#
            ))
            .bind(search)
            .fetch_one(&self.pool)
            .await
            .map_err(DbBrowseError::database)
        }
    }
}
