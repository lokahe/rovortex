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
│   └── DATABASE.md          # 数据库与访问层选型分析报告
└── crates/
    ├── users/               # 用户业务模块（纯业务，框架无关）
    │   └── src/
    │       ├── lib.rs           # 模块导出
    │       ├── domain.rs        # User 实体、校验规则、UserError
    │       ├── password.rs      # Argon2id 哈希 / 校验
    │       ├── repository.rs    # UserRepository 抽象契约
    │       ├── service.rs       # UserService：register / login 用例
    │       └── in_memory.rs     # 内存仓储（数据库落地前过渡实现）
    └── gateway_api/         # 程序入口（表现层）
        └── src/
            ├── main.rs          # Tokio 运行时、路由挂载、优雅停机
            ├── state.rs         # AppState：组合根（依赖注入）
            ├── error.rs         # 业务错误 → HTTP 状态码映射
            └── routes/          # HTTP 接口
                ├── mod.rs           # 路由装配
                ├── health.rs        # GET  /health
                └── users.rs         # 注册 / 登录接口
```

## 技术栈

| 层次 | 选型 | 说明 |
|------|------|------|
| 语言 | Rust 2024 edition | 内存安全 + 高性能 |
| Web 框架 | axum 0.8 | Tokio 官方生态，tower 中间件体系 |
| 异步运行时 | Tokio | 工业界事实标准 |
| 密码哈希 | Argon2id（argon2 crate） | OWASP 推荐，PHC 格式自嵌盐与参数 |
| ID 生成 | UUID v7 | 时间有序，数据库索引友好 |
| 错误处理 | thiserror | 领域错误定义 |
| 可观测性 | tracing + tracing-subscriber | 结构化日志，`RUST_LOG` 控制 |
| 持久化 | trait 抽象（当前 in-memory） | 数据库选型见 [docs/DATABASE.md](docs/DATABASE.md) |

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
```

错误响应统一为 `{"error":{"code":"...","message":"..."}}`：
重复注册 → `409 conflict`；参数非法 → `400 invalid_request`；凭据错误 → `401 invalid_credentials`。

## 模块化扩展指南

新增业务模块（如 `billing`）：

1. `cargo new crates/billing --lib`，加入 workspace `members`；
2. 定义自己的领域模型与仓储 trait（参照 `crates/users/src/repository.rs`）；
3. 在 `gateway_api/src/state.rs` 注入实现，在 `routes/` 暴露 HTTP 接口；
4. 跨模块协作时通过服务接口或领域事件，**禁止**直接读取他模块的存储。

## 演进路线

| 阶段 | 内容 | 状态 |
|------|------|------|
| Phase 1 | 项目骨架 + 注册/登录 + Argon2id + 内存仓储 | ✅ 本次交付 |
| Phase 2 | JWT 访问/刷新令牌、登录限流 | ⏳ |
| Phase 3 | 数据库落地（PostgreSQL + sqlx，见 docs/DATABASE.md）、迁移脚本 | ⏳ 选型确认后 |
| Phase 4 | 邮箱验证、密码重置、审计日志 | ⏳ |
| Phase 5 | RBAC 权限、第三方 OAuth、更多业务模块 | ⏳ |

详细设计见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。
