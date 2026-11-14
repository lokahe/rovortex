# 认证体系 v2 设计：OAuth 一键登录 + 邮箱 Magic Link（全程免密）

> 状态：**设计稿（未实施）**。P1（refresh token / 改密码 / 会话管理）落地后启动。
> 前置阅读：docs/ARCHITECTURE.md（分层）、docs/DATABASE.md（选型）。

## 1. 目标

在现有密码体系之上，新增三类认证方式，做到**全程免密可选**：

| 方式 | 场景 | 免密？ |
|------|------|--------|
| OAuth（Google / Apple / GitHub / X） | 一键注册登录 | ✅ |
| Magic Link（邮箱链接登录） | 无第三方账号、邮箱验证 | ✅ |
| 密码 | 存量用户 / 保守用户 | ❌（保留，不强制） |

一个账号可同时绑定多种方式（如 GitHub + Google + 密码），共用同一个 user。

## 2. 现状与差距

当前（P0/P1 后）：

```
users 表：password_hash TEXT NOT NULL          ← 密码必填，硬编码进 schema
User { password_hash: String }                 ← 领域模型必填
UserService::login 只有一条路：password verify  ← 认证方式单一
```

差距：
1. `password_hash` 不可为 NULL —— OAuth/Magic 用户没有密码，无法建模
2. 没有「外部身份」概念 —— 无法记录“这个 user 对应 GitHub 上的谁”
3. 没有邮件基础设施 —— Magic Link 需要发信

## 3. Schema 设计（迁移 0003、0004）

### 0003：user_identities 表（核心）

```sql
CREATE TABLE user_identities (
    id            UUID PRIMARY KEY,              -- UUIDv7 应用侧生成
    user_id       UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider      TEXT        NOT NULL,          -- 'google' | 'apple' | 'github' | 'x' | 'magic'
    provider_uid  TEXT        NOT NULL,          -- 平台侧唯一 id；magic 时为邮箱本身
    email         TEXT,                          -- 平台报告的邮箱（可能为空，X 就不给）
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_uid)              -- 一个外部身份只能绑定一个账号
);
CREATE INDEX user_identities_user_id_idx ON user_identities (user_id);
```

设计要点：
- `UNIQUE(provider, provider_uid)` 是 OAuth 登录的查找主键：回调拿到 `(provider, uid)`
  后一条 SELECT 判断「老用户直接登录 / 新用户自动注册」
- 同一 user 可有多行（多平台绑定）；同一外部身份只能属于一个 user（防账号合并歧义）
- `provider = 'magic'` 特殊行表示“这个邮箱验证过”，magic link 登录即查/建此身份
- 迁移时为存量密码用户补建 `('password', <user_id>)` 身份行？**不需要**——密码
  不是外部身份，`password_hash` 是否为 NULL 才是判断依据

### 0004：password_hash 可空化

```sql
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
```

领域模型同步改动：

```rust
pub struct User {
    // ...
    pub password_hash: Option<String>,   // None = 无密码（纯 OAuth/Magic 用户）
}
pub struct NewUser {
    // ...
    pub password_hash: Option<String>,
}
```

语义规则（业务层强制）：
- `password_hash == None` 时，密码登录返回 `InvalidCredentials`（不提示“未设置密码”，防枚举）
- 绑定过任一 OAuth 的账号才允许 `password_hash` 为 None
- 「设置密码」用例：为 None 的账号设初值，不需要验旧密码；已有的则必须验旧密码

### email 唯一性的重新审视

现状：`email_key` 生成列 + 唯一索引，邮箱全局唯一。
v2 保持不变——所有 provider 都要求报告 verified email 才允许绑定（X 若报
unverified 邮箱则拒绝绑定并要求 magic link 验证），保证 email 仍是账号的
稳定锚点。将来若要支持「同邮箱多账号」再改，目前无此需求。

## 4. 分层归属（严格遵守现有架构）

```
crates/users/                     ← 业务层：框架无关，不出现 HTTP/OAuth 字眼
├── domain.rs                     User.password_hash → Option
├── oauth_identity.rs (新)        ExternalIdentity { provider, provider_uid, email }
│                                 + OauthIdentityRepository trait（find_by_external /
│                                   create_for_user / list_for_user / remove）
├── service.rs                    新用例：
│                                   login_with_identity(provider, uid, email) -> Session
│                                     （存在即登录，不存在自动建用户，用户名自动生成+去重）
│                                   link_identity(user_id, ...) / unlink_identity(...)
│                                   set_password(user_id, new)      （None→Some 免旧密码）
└── auth.rs                       不变

crates/gateway_api/               ← 表现层：协议栈全部住这里
├── routes/oauth.rs (新)          GET /api/auth/oauth/<provider>        → 302 跳平台授权页
│                                 GET /api/auth/oauth/<provider>/callback
│                                   → code 换 token → 拉用户信息 → 提取 (provider, uid, email)
│                                   → state.users.login_with_identity(...) → 签发会话
├── routes/magic.rs (新)          POST /api/auth/magic-link { email }   → 发信（一次性 token 入库）
│                                 GET  /api/auth/magic-link/verify?token=→ 校验 → 建身份 → 签发会话
└── oauth/ (新, 私有 mod)         各 provider 客户端（token 交换、用户信息拉取），
                                  每家一个 struct 实现 OAuthProvider trait
```

关键决策：**OAuth 协议细节不进业务层**。业务层只见「外部身份三元组」，
换/加平台（如以后接微信）只改 gateway_api 的 provider 客户端，业务零改动。
这是「先抽象后落地」策略在认证域的复用。

## 5. 安全设计

| 项 | 方案 |
|----|------|
| OAuth `state` 参数 | 随机值 + HttpOnly cookie 短暂保存，回调时比对，防 CSRF |
| 回调错误处理 | 平台拒绝授权 → 302 回前端错误页，不暴露内部细节 |
| Magic link token | 一次性（用后即吊销）、15 分钟过期、SHA-256 哈希落库（复用 refresh_tokens 的哈希约定） |
| 发信频率限制 | 同邮箱 1 分钟 1 条、1 小时 5 条（先内存实现，量大再上 Redis——基础设施演进点） |
| 账号合并 | 同 email 已存在时：登录既有账号并把新 provider 身份挂上去（ NOT 新建第二个账号） |
| 会话 | 与密码登录完全一致：Session { access JWT + refresh token }，P1 全套复用 |

## 6. 平台接入顺序与工作量

| 顺序 | Provider | 理由 | 后端工作量 |
|------|----------|------|-----------|
| 1 | GitHub | OAuth App 免审核、文档清晰、开发群体匹配 | ~1 天 |
| 2 | Google | 用户量大；需 Google Cloud Console 配置 | ~1 天 |
| 3 | Apple | 若做 iOS 端必需；要求开发者账号 + 域名验证 | ~1-2 天 |
| 4 | X (Twitter) | OAuth 2.0 PKCE，用户重叠度低，优先级最低 | ~1 天 |
| 5 | Magic Link | 依赖 SMTP 选型（Resend 免费档 100 封/天起步够用） | ~1-2 天 |

各 provider 共用同一套路由 + trait，新增平台主要是填 client 参数。

## 7. 迁移与回滚

- 0003/0004 都是**纯增量**迁移：不动现有行，密码用户完全无感
- `Option<String>` 改动会波及 `query_as!` 的类型推导和全部 `.password_hash`
  引用处，编译器会逐个指出——借编译期校验逐个确认
- 灰度顺序：先合 0003（加表，无行为变化）→ 部署观察 → 再合 0004+用例（行为变化）
- 回滚：功能开关（环境变量 `ROVORTEX_OAUTH_ENABLED`）控制路由挂载，
  出问题关掉即回纯密码模式，schema 不用回滚

## 8. 明确不做（v2 范围外）

- 账号删除 / GDPR 数据导出（等有真实用户诉求）
- 多租户 / 组织（RBAC 的前置，架构演进期再说）
- 手机号登录（需要短信基础设施，成本高收益低）
- WebAuthn/Passkey（好东西，但等 OAuth 稳定后再评估）
