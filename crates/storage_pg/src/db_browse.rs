//! `rovortex_users::DbBrowser` 的 PostgreSQL 实现。
//!
//! 动态表/列标识符来自业务层白名单校验后的值（不能走绑定参数），
//! 值参数照常绑定。占位符按有无 WHERE 分支生成：
//! 搜索时 $1=q/$2=limit/$3=offset，否则 $1=limit/$2=offset。

use serde_json::Value;
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use rovortex_users::db_browse::{
    BROWSABLE_TABLES, BrowseParams, ColumnInfo, DbBrowseError, DbBrowser, TableSummary,
};

pub struct PgDbBrowser {
    pool: sqlx::PgPool,
}

impl PgDbBrowser {
    pub fn from_pool(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// 批量查列类型并校验列确实属于该表（GENERATED 列已在网关层挡掉）。
    /// 返回顺序与 `columns` 一致（information_schema 的类型名可直接拼 CAST）。
    async fn column_types(
        &self,
        table: &str,
        columns: &[(String, Value)],
    ) -> Result<Vec<String>, DbBrowseError> {
        let valid = self.describe(table).await?;
        columns
            .iter()
            .map(|(name, _)| {
                valid
                    .iter()
                    .find(|c| c.name == name.as_str())
                    .map(|c| c.data_type.clone())
                    .ok_or_else(|| DbBrowseError::UnknownColumn(name.clone()))
            })
            .collect()
    }
}

/// JSON 值 → PG 文本字面量（随后 CAST 成列类型）：
/// null 保持 NULL 语义（None），其余取原始标量值。
/// 注意不能用 Value::to_string()——那是 JSON 序列化，String 会带上引号。
fn value_as_text(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::Bool(b) => Some(b.to_string()),
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        // 数组/对象（当前白名单列用不到）走 JSON 文本，PG 端可 CAST 解析
        other => Some(other.to_string()),
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

    /// 值统一按 TEXT 绑定，由 `CAST($n AS <列类型>)` 转成目标类型——
    /// serde_json::Value 直接绑定会被 sqlx 声明成 jsonb，遇到 varchar/bool/
    /// timestamptz 列必然报类型不符。列类型来自 describe（information_schema）。
    async fn insert_row(
        &self,
        table: &str,
        columns: &[(String, Value)],
    ) -> Result<Uuid, DbBrowseError> {
        let types = self.column_types(table, columns).await?;
        let id = Uuid::now_v7();
        let placeholders: Vec<String> = columns
            .iter()
            .enumerate()
            .map(|(i, _)| format!("CAST(${} AS {})", i + 2, types[i]))
            .collect();
        let names: Vec<&str> = columns.iter().map(|(n, _)| n.as_str()).collect();
        let sql = format!(
            "INSERT INTO {table} (id, {}) VALUES ($1, {}) RETURNING id",
            names.join(", "),
            placeholders.join(", "),
        );
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql).bind(id);
        for (_, v) in columns {
            q = q.bind(value_as_text(v));
        }
        q.fetch_one(&self.pool)
            .await
            .map_err(DbBrowseError::database)
    }

    async fn update_row(
        &self,
        table: &str,
        id: Uuid,
        columns: &[(String, Value)],
    ) -> Result<u64, DbBrowseError> {
        let types = self.column_types(table, columns).await?;
        let sets: Vec<String> = columns
            .iter()
            .enumerate()
            .map(|(i, (n, _))| format!("{n} = CAST(${} AS {})", i + 1, types[i]))
            .collect();
        let id_ph = columns.len() + 1;
        let sql = format!("UPDATE {table} SET {} WHERE id = ${id_ph}", sets.join(", "));
        let mut q = sqlx::query(&sql);
        for (_, v) in columns {
            q = q.bind(value_as_text(v));
        }
        let res = q
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(DbBrowseError::database)?;
        Ok(res.rows_affected())
    }

    async fn delete_row(&self, table: &str, id: Uuid) -> Result<u64, DbBrowseError> {
        let res = sqlx::query(&format!("DELETE FROM {table} WHERE id = $1"))
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(DbBrowseError::database)?;
        Ok(res.rows_affected())
    }
}
