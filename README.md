# Rovortex

基于 [Axum](https://github.com/tokio-rs/axum) 的**模块化单体（Modular Monolith）**次世代后端。
以业务模块为边界组织代码：模块内部高内聚、模块之间低耦合，未来既可整体部署，也可按模块平滑拆分为微服务。

## 架构总览

```
                        ┌─────────────────────────────┐
   HTTP Request ──────▶ │  gateway_api（表现层）        │
                        │  · Axum 路由 / DTO / 错误映射 │
                        │  · main.rs: Tokio 启动       │
                        └──────────────┬──────────────┘
                                       │ 调用业务接口（依赖单向向下）
                        ┌──────────────▼──────────────┐
                        │  users（核心业务层）          │
                        │  · UserService: 注册/登录用例 │
                        │  · domain: 实体与领域校验      │
                        │  · password: Argon2id 哈希    │
                        │  · UserRepository trait      │
                        └──────────────┬──────────────┘
                                       │ 实现（组合根注入，可替换）
                        ┌──────────────▼──────────────┐
                        │  持久化实现                   │
                        │  · in_memory（当前）          │
                        │  · storage_pg（规划，PG+sqlx）│
                        └─────────────────────────────┘
```

核心原则：**依赖只能自上而下**（表现层 → 业务层 → 抽象），业务层永远不感知 HTTP/JSON/数据库细节。

## 目录结构

```
rovortex/
├── Cargo.toml               # Workspace：统一版本管理（[workspace.dependencies]）
├── docs/
│   ├── ARCHITECTURE.md      # 架构决策、模块边界、演进路线图
│   ├── DATABASE.md          # 数据库与访问层选型分析报告
│   └── AUTH_V2.md           # 认证体系 v2 设计（OAuth / Magic Link）
└── crates/
    ├── users/               # 用户业务模块（纯业务，框架无关）
    │   └── src/
    │       ├── lib.rs           # 模块导出
    │       ├── domain.rs        # User 实体、校验规则、UserError
    │       ├── password.rs      # Argon2id 哈希 / 校验
    │       ├── repository.rs    # UserRepository 抽象契约
    │       ├── oauth_identity.rs # 外部身份（GitHub / magic）+ 仓储 trait
    │       ├── audit.rs         # 安全审计事件与仓储 trait
    │       ├── service.rs       # UserService：注册 / 登录 / OAuth 合并等用例
    │       └── ...
    ├── storage_pg/          # PostgreSQL + sqlx 实现（各仓储 trait 的生产实现）
    ├── infra_mail/          # Resend 邮件发送（MailSender trait 实现）
    └── gateway_api/         # 程序入口（表现层）
        └── src/
            ├── main.rs          # Tokio 运行时、路由挂载、优雅停机
            ├── state.rs         # AppState：组合根（依赖注入）
            ├── error.rs         # 业务/HTTP 错误 → 统一错误响应
            ├── observe.rs       # request_id 访问日志 + 指标采集中间件
            ├── rate_limit.rs    # 登录失败限流（LoginGuard 内存实现）
            ├── mail_rate_limit.rs # Magic Link 发信限流（1/分钟 + 5/小时）
            └── routes/          # HTTP 接口
                ├── mod.rs           # 路由装配
                ├── health.rs        # GET  /health
                ├── users.rs         # 注册 / 登录接口
                ├── session.rs       # 刷新 / 吊销会话
                ├── oauth.rs         # GitHub OAuth 授权 / 回调
                └── magic.rs         # Magic Link 请求 / 验证
```

## 技术栈

| 层次 | 选型 | 说明 |
|------|------|------|
| 语言 | Rust 2024 edition | 内存安全 + 高性能 |
| Web 框架 | axum 0.8 | Tokio 官方生态，tower 中间件体系 |
| 异步运行时 | Tokio | 工业界事实标准 |
| 数据库 | PostgreSQL + sqlx（编译期校验 SQL） | 迁移随应用启动自动执行 |
| 密码哈希 | Argon2id（argon2 crate） | OWASP 推荐，PHC 格式自嵌盐与参数 |
| 认证 | JWT access + refresh 轮换；GitHub OAuth；邮箱 Magic Link | 全程免密可选 |
| 邮件 | Resend HTTP API | 域名已验证 |
| ID 生成 | UUID v7 | 时间有序，数据库索引友好 |
| 错误处理 | thiserror | 领域错误定义 |
| 可观测性 | tracing + tracing-subscriber | 结构化日志 + request_id 贯穿，`RUST_LOG` 控制 |

## 快速开始

环境要求：Rust 1.85+（含 cargo）。

```powershell
# 编译
cargo build

# 运行单元测试
cargo test

# 启动服务（默认 0.0.0.0:8080，可用 ROVORTEX_PORT 覆盖）
cargo run -p rovortex-gateway-api
```

### 接口演示

```powershell
# 健康检查
curl http://localhost:8080/health
# → {"status":"ok"}

# 注册
curl -X POST http://localhost:8080/api/users/register `
  -H "Content-Type: application/json" `
  -d '{"username":"alice","email":"alice@example.com","password":"Str0ng-pass!"}'
# → 201 {"user":{"id":"0192...","username":"alice","email":"alice@example.com","created_at":"..."},"token":null}

# 登录（用户名或邮箱均可）
curl -X POST http://localhost:8080/api/users/login `
  -H "Content-Type: application/json" `
  -d '{"login":"alice@example.com","password":"Str0ng-pass!"}'

# GitHub OAuth（浏览器打开，302 跳 GitHub 授权页；需配置 OAUTH_GITHUB_CLIENT_ID/SECRET）
start http://localhost:8080/api/auth/oauth/github

# Magic Link（响应恒为 202；未知邮箱会在点击链接时自动注册——防枚举）
curl -X POST http://localhost:8080/api/auth/magic-link `
  -H "Content-Type: application/json" `
  -d '{"email":"alice@example.com"}'
# 点击邮件中的链接 → GET /api/auth/magic-link/verify?token=... → 会话 JSON
```

### 认证端点一览

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/users/register` · `/api/users/login` | POST | 密码注册 / 登录 |
| `/api/auth/refresh` · `/api/auth/logout` | POST | 刷新（轮换）/ 吊销会话 |
| `/api/auth/verify-email/request` · `/confirm` | POST / GET | 邮箱验证 |
| `/api/auth/email-change/confirm` | GET | 改邮箱确认 |
| `/api/auth/oauth/github` · `/callback` | GET | GitHub OAuth 登录 |
| `/api/auth/magic-link` · `/verify` | POST / GET | Magic Link 登录 |
| `/api/auth/password-reset/request` · `/confirm` | POST / GET | 找回密码（响应恒 202，防枚举） |
| `/api/users/me` | GET | 当前用户（Bearer JWT） |
| `/api/users/me/password` · `/me/email` · `/me/username` | PUT | 改密码 / 改邮箱 / 改用户名 |
| `/api/users/me/profile` | PATCH | 改资料（部分更新 / 清空字段） |
| `/api/users/me/identities` · `/identities/{provider}` | GET / DELETE | 已绑定外部身份列表 / 解绑（须保留至少一种登录方式） |
| `/api/users/me/sessions` · `/sessions/{id}` | GET / DELETE | 有效会话列表（设备/UA/粗粒度 IP）/ 踢掉指定设备 |
| `/api/admin/users` · `/users/{id}` · `/users/{id}/ban` · `/users/{id}/force-logout` · `/stats` | GET/PUT/POST | 管理接口（is_admin 实时校验） |
| `/health` · `/metrics` | GET | 健康检查 / Prometheus 指标 |

错误响应统一为 `{"error":{"code":"...","message":"..."}}`：
重复注册 → `409 conflict`；参数非法 → `400 invalid_request`；凭据错误 → `401 invalid_credentials`；限流 → `429 too_many_requests`。

## 模块化扩展指南

新增业务模块（如 `billing`）：

1. `cargo new crates/billing --lib`，加入 workspace `members`；
2. 定义自己的领域模型与仓储 trait（参照 `crates/users/src/repository.rs`）；
3. 在 `gateway_api/src/state.rs` 注入实现，在 `routes/` 暴露 HTTP 接口；
4. 跨模块协作时通过服务接口或领域事件，**禁止**直接读取他模块的存储。

## 演进路线

| 阶段 | 内容 | 状态 |
|------|------|------|
| Phase 1 | 项目骨架 + 注册/登录 + Argon2id + 内存仓储 | ✅ |
| Phase 2 | JWT 访问/刷新令牌、登录限流 | ✅ |
| Phase 3 | PostgreSQL + sqlx 落地（编译期校验 + 自动迁移） | ✅ |
| Phase 4 | 邮箱验证、审计日志、访问日志、/metrics | ✅ |
| Phase 5 | GitHub OAuth + Magic Link 免密登录 | ✅ |
| Phase 6 | 找回密码、改用户名、用户资料（含平台资料回填/解绑）、会话管理（列表/踢设备）、admin 强制下线 | ✅ |
| Phase 7 | RBAC 权限、更多业务模块 | ⏳ |

详细设计见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)、[docs/AUTH_V2.md](docs/AUTH_V2.md)。
