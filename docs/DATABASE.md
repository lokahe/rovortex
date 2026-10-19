# 数据库选型分析报告

- 状态：**已确认**（PostgreSQL 16+ + sqlx）。按 §5 集成方案落地，业务代码零改动；

## 1. 需求画像（用户系统视角）

- 强一致性：用户名/邮箱唯一约束、注册事务性；
- 读多写少：登录/资料读取频率远高于注册；
- 未来扩展：审计日志、RBAC、全文检索（用户搜索）、可能的向量检索（AI 特性）；
- 团队规模小，优先零/低成本运维；云托管可用性优先。

## 2. 候选数据库对比

| 维度 | PostgreSQL 16+ | MySQL 8 | SQLite | MongoDB |
|------|----------------|---------|--------|---------|
| 事务与唯一约束 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐（4.0+ 才有多文档事务） |
| JSON 能力 | JSONB + GIN 索引 | JSON 一般 | JSON 函数有限 | 原生文档模型 |
| Rust 生态支持 | sqlx/SeaORM/Diesel 最佳 | 良好 | 良好（rusqlite/sqlx） | 官方 driver 一般 |
| 扩展性 | pgvector、pg_trgm、分区表、RLS | 插件较少 | — | — |
| 运维成本 | 中（建议容器/云托管） | 中 | 极低（单文件） | 中 |
| 并发写入 | MVCC，优秀 | 优秀 | 单写者（WAL 下读写并发） | 优秀 |
| 适配本项目 | **最佳** | 可行 | 仅开发/单机 | 不推荐 |

**结论：推荐 PostgreSQL。** 用户系统的强关系 + 唯一约束 + 事务诉求与 PG 完美匹配；
pgvector/pg_trgm 为后续 AI 特性与用户搜索预留能力；Rust 社区资源最丰富。

SQLite 可作为**本地开发/测试**的轻量选择（sqlx 同一套 API），但生产不建议。
MySQL 是合理的第二选择，若团队已有深度运维经验可采纳。

## 3. Rust 数据访问层对比

| 维度 | sqlx ⭐推荐 | SeaORM | Diesel |
|------|------------|--------|--------|
| 模式 | 原生 SQL + 编译期校验（`query!`） | 基于 sqlx 的 ORM | DSL 级类型安全 ORM |
| 异步 | 原生 async | 原生 async | 同步为主（diesel-async 补充） |
| 迁移 | 内置 `sqlx migrate` | sea-orm-migration | diesel_migrations |
| 离线编译 | 支持（`cargo sqlx prepare`） | 支持 | 支持 |
| 学习曲线 | 低（会 SQL 即可） | 中 | 高（宏推导报错难懂） |
| 适合 | 精确控制 SQL、性能敏感 | 快速 CRUD 迭代 | 极致类型安全偏好者 |

**结论：推荐 sqlx。** 用户系统 SQL 面积小（几张表、明确约束），原生 SQL + 编译期校验
能最大程度避免运行时 SQL 错误；迁移与离线模式成熟。SeaORM 可在 CRUD 密集的模块按需引入。

## 4. Schema 草案（users 表）

```sql
CREATE TABLE users (
    id            UUID PRIMARY KEY,                       -- UUIDv7，应用侧生成
    username      TEXT        NOT NULL,
    username_key  TEXT        NOT NULL GENERATED ALWAYS AS (lower(username)) STORED,
    email         TEXT        NOT NULL,
    email_key     TEXT        NOT NULL GENERATED ALWAYS AS (lower(email)) STORED,
    password_hash TEXT        NOT NULL,                   -- PHC 格式 Argon2id
    status        SMALLINT    NOT NULL DEFAULT 0,         -- 0=active（预留封禁等状态）
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 大小写不敏感唯一约束（对齐 in_memory 实现的 lower() 语义）
CREATE UNIQUE INDEX users_username_uniq ON users (username_key);
CREATE UNIQUE INDEX users_email_uniq    ON users (email_key);
CREATE INDEX users_created_at_idx ON users (created_at);
```

> `GENERATED ... STORED` 列实现大小写不敏感唯一性，与当前内存实现的语义完全一致 ——
> 这是"先抽象后落地"策略的直接受益：契约不变，仅实现替换。

## 5. 集成方案（模块化单体的可替换性验证）

```
crates/
├── users/          # 不动：UserRepository trait 已就位
├── storage_pg/     # 新增：sqlx PgPool 实现 UserRepository
└── gateway_api/    # 仅改 state.rs 一处：按配置选择注入实现
```

- `AppState::new()` 按环境变量（如 `ROVORTEX_DB=url`）选择 `InMemory` 或 `Pg` 实现；
- 单元测试继续用 in-memory（快、无外部依赖），PG 实现配集成测试（testcontainers 或专用测试库）；
- 迁移工具：`sqlx migrate`；本地开发数据库：docker-compose 起 PG 容器：

```yaml
# docs 片段，选型确认后移至项目根目录 docker-compose.yml
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: rovortex
      POSTGRES_PASSWORD: rovortex_dev
      POSTGRES_DB: rovortex
    ports: ["5432:5432"]
    volumes: [rovortex_pgdata:/var/lib/postgresql/data]
volumes:
  rovortex_pgdata:
```

## 6. 决策记录

|| 项 | 建议 | 状态 |
||----|------|------|
|| 数据库 | PostgreSQL 16+ | ✅ 已确认 |
|| 访问层 | sqlx | ✅ 已确认 |
|| 本地开发 | docker-compose PG 容器 | ✅ 已确认 |
|| 迁移 | sqlx migrate | ✅ 已确认 |
