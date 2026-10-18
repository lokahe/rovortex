# Rovortex 架构决策记录（ADR）

## 1. 架构风格：模块化单体（Modular Monolith）

**决策**：以 Workspace 多 crate 组织代码，每个业务域一个 crate（当前仅 `users`），单一可执行入口 `gateway_api`。

**理由**：
- 相比微服务：无网络开销、无分布式事务、单进程部署运维简单；
- 相比单 crate 大泥球：编译增量、边界由编译器强制（crate 间只能通过显式 `pub` API 交互）、团队可并行；
- 演进友好：任何模块未来可独立抽出为服务（其 trait 边界与 HTTP API 已经就位）。

**依赖规则（编译器强制）**：

```
gateway_api ──▶ users ──▶ （无，业务层零框架依赖）
    │              ▲
    └── 注入仓储实现 ┘
```

- `users` 禁止依赖 axum / serde / 数据库驱动 —— 由 CI 检查（后续可加 `cargo-deny`）；
- 表现层只做：协议适配（JSON DTO）、状态码映射、依赖注入；
- 业务层只做：领域规则、用例编排、发布抽象。

## 2. 用户系统设计

### 实体

| 字段 | 类型 | 说明 |
|------|------|------|
| id | UUID v7 | 时间有序，B 树索引友好；由仓储实现生成 |
| username | String | 3-32 字符，字母开头，`[A-Za-z0-9_]`；大小写不敏感唯一 |
| email | String | 格式门槛校验；大小写不敏感唯一；送达确认在 Phase 4 |
| password_hash | String | PHC 格式 Argon2id，禁止序列化出业务层 |

### 用例

- **register(username, email, password)**：领域校验 → 查重（用户名/邮箱）→ Argon2id 哈希 → 持久化；
- **login(login, password)**：`login` 兼容用户名或邮箱 → 校验哈希。

### 安全决策

1. **Argon2id** 而非 bcrypt/scrypt：OWASP 2024 首选推荐，抗 GPU/ASIC；
2. **防账号枚举**：登录失败统一 `InvalidCredentials`，响应不区分“用户不存在/密码错误”；
3. **防时序侧信道**：argon2 的 `PasswordVerifier` 为常数时间比较；
4. **唯一性双重保险**：服务层预检查（快速友好错误）+ 仓储层强制唯一（并发正确性，数据库阶段用唯一索引）；
5. **密码不出业务层**：`User` 实体不实现 Serialize，对外 DTO 由表现层显式构造。

## 3. 错误处理流

```
UserError（users，thiserror）
    └─▶ ApiError（gateway_api，IntoResponse）
            ├─ UsernameTaken / EmailTaken      → 409 CONFLICT
            ├─ InvalidUsername/Email/Password  → 400 BAD_REQUEST
            ├─ UserNotFound                    → 404 NOT_FOUND
            ├─ InvalidCredentials              → 401 UNAUTHORIZED
            └─ Hashing（意外）                  → 500 + error! 日志
```

## 4. 依赖注入（组合根模式）

- 仓储契约 `UserRepository`（`#[async_trait]`，对象安全）定义在 `users`；
- 具体实现以 `Arc<dyn UserRepository>` 注入 `UserService`；
- 唯一组装点：`gateway_api::state::AppState::new()` —— 数据库落地后只改这一个函数。

## 5. 演进路线图

| 阶段 | 内容 | 关键 crate |
|------|------|-----------|
| Phase 1 ✅ | 骨架 + 注册/登录 + Argon2id + in-memory | axum, tokio, argon2 |
| Phase 2 | JWT 双令牌、登录限流、refresh 轮换 | jsonwebtoken, tower (rate limit) |
| Phase 3 | PostgreSQL 落地（见 DATABASE.md）、迁移 | sqlx, storage_pg |
| Phase 4 | 邮箱验证、密码重置、审计日志 | lettre |
| Phase 5 | RBAC、OAuth2 第三方登录、新业务模块 | — |

## 6. 待决策项

- [ ] 数据库选型确认（推荐 PostgreSQL + sqlx，详见 docs/DATABASE.md）
- [ ] 会话策略：JWT（无状态）vs 服务端会话（可撤销）—— Phase 2 前定
- [ ] 观测后端：OTLP → Prometheus/Grafana 或 Jaeger
