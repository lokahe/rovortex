# 用户资料体系设计：OAuth 资料同步 + 自助资料编辑（P6-2）

> 状态：**设计稿（待确认后实施）**。
> 前置阅读：docs/AUTH_V2.md（外部身份模型）、docs/DATABASE.md（users 表）。
> 范围：缺口分析 #2（OAuth 注册未同步头像/名称）+ #3（用户无法自助编辑资料）。

## 1. 目标

1. **资料同步**：GitHub OAuth 注册/登录时，把平台的头像、显示名、个人主页等
   带回并存到 users 表；已有账号再次登录时按策略刷新。
2. **资料编辑**：用户可以自助修改「展示层字段」（显示名、头像、简介、主页），
   与「账号锚点字段」（用户名、邮箱——已有独立流程）分开。

## 2. 字段设计（迁移 0009）

双层结构：**users 表存规范字段（canonical），user_identities 存各平台原始资料（raw JSONB）**。

### 2.1 users 表加列（规范字段，固定列）

```sql
-- 0009_add_profile.sql
ALTER TABLE users
    ADD COLUMN display_name TEXT,          -- 展示名（可空 = 用 username）
    ADD COLUMN avatar_url   TEXT,          -- 头像 URL（可空 = 前端默认头像）
    ADD COLUMN bio          TEXT,          -- 简介（可空，<= 280 字符，业务层校验）
    ADD COLUMN website_url  TEXT;          -- 个人主页（可空，业务层校验 http(s)://）
```

设计要点：

- **全部可空**：存量用户无感；无资料的行不占认知负担，前端 fallback 到
  `username` + 默认头像。不设 DEFAULT，避免误造「空字符串资料」。
- **username 保持唯一锚点不动**：display_name 不唯一、可随意改；
  登录名/审计/搜索仍以 username/email 为准。两套字段职责分离。
- **不做单独 profiles 表**：字段 4 个、1:1 关系，join 收益为零，
  直接加列符合 DATABASE.md 的「SQL 面积小」原则。
- bio/website 放在本次一起加列（纯增量、零风险），避免二次迁移。
- 业务层读到的永远是这 4 个规范字段——前端展示只依赖 users 行，
  不需要知道资料源自哪个平台。

### 2.2 user_identities 加列（各平台原始资料，JSONB）

```sql
ALTER TABLE user_identities
    ADD COLUMN raw_profile JSONB;          -- 平台返回的原始资料缓存（可空）
```

- **key 由 provider 决定、不可预知**（github 的 `blog`、google 的 `picture`、
  weixin 的 `headimgurl`...）——这正是 JSONB 的合理场景，users 表保持固定列。
- 网关层抓到平台资料后原样（或裁剪后）序列化存入；登录/绑定身份时顺带写。
- **用途**：未来用户可在设置页选择「头像用 GitHub 的 / 名字用 Google 的」，
  直接从 raw_profile 取值回填规范字段，无需重新调平台 API；
  也保留审计与调试能力（当时平台到底返回了什么）。
- magic 行不写 raw_profile（无资料来源）。
- 不建 GIN 索引：不查询 JSONB 内部，只按 user_id+provider 整行读取。

## 3. GitHub 资料来源与同步策略

### 3.1 抓取（gateway_api/routes/oauth.rs）

`GithubUser` 扩展字段（GET /user 已返回，无额外请求）：

```rust
#[derive(Deserialize)]
struct GithubUser {
    id: i64,
    email: Option<String>,
    login: String,             // github 用户名（用于 display_name fallback）
    name: Option<String>,      // 设置的显示名
    avatar_url: String,        // 头像（GitHub 恒有）
    blog: Option<String>,      // 个人主页（无协议时补 https:// 或丢弃）
    bio: Option<String>,       // 简介
}
```

### 3.2 传递（业务层只见数据不见协议）

`login_with_identity` 增加可选 profile 参数（网关把抓到的资料打包传入）：

```rust
pub struct ExternalProfile {          // 放 crates/users（domain 或 oauth_identity.rs）
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub bio: Option<String>,
    pub website_url: Option<String>,
    /// 平台原始 JSON（网关层已裁剪敏感字段如 access_token），存 user_identities.raw_profile
    pub raw: Option<serde_json::Value>,
}

login_with_identity(provider, uid, email, profile: Option<ExternalProfile>, ip)
```

业务层不出现 "github" 字眼——延续 AUTH_V2.md §4 的「协议细节不进业务层」。
`ExternalProfile.raw` 与 4 个规范字段一起传入：规范字段走回填逻辑进 users，
raw 整体落 user_identities.raw_profile。find_by_external 查到已有身份时
顺带刷新 raw（平台资料最新值），users 规范字段仍按「空缺才回填」不动。

### 3.3 同步策略（写回时机）

| 场景 | 行为 |
|------|------|
| 新用户自动注册 | 直接写入资料（首体验最重要） |
| 已绑定用户，users 表该字段为空 | 回填（填补空缺，无覆盖风险） |
| 已绑定用户，users 表该字段非空 | **不覆盖**（用户可能已在 rovortex 改过） |

不覆盖原则的理由：OAuth 资料只是「初始值来源」，一旦用户在我们这里编辑过
（非空即视为编辑过），平台侧更新不应反向覆盖。简单、可预期、无 diff 跟踪成本。
Magic Link 登录没有资料来源，profile 传 None，行为不变。

### 3.4 用户名自动生成的优化（顺带）

现在 `unique_username_from(email)` 用邮箱前缀。加 profile 后新用户可优先用
`github login`（如 `lokahe619`），冲突时退回邮箱前缀方案。纯优化，不改变
唯一性约束与校验规则。

## 4. 自助编辑用例（业务层 UserService）

```rust
pub struct UpdateProfile {           // 全 Option：None = 不动，Some 值 = 更新
    pub display_name: Option<Option<String>>,   // Some(None) = 清空
    pub avatar_url: Option<Option<String>>,
    pub bio: Option<Option<String>>,
    pub website_url: Option<Option<String>>,
}

pub async fn update_profile(&self, user_id: Uuid, patch: UpdateProfile, ip) -> Result<User, UserError>
```

- 校验：display_name ≤ 64 字符；bio ≤ 280；website_url 必须 http(s):// 开头
  且 ≤ 256；avatar_url 同 website_url（防 XSS：只存 URL，渲染时由前端控制）。
- 审计：新增 `AuditAction::ProfileUpdated`（"profile_updated"）。
- **不吊销会话**：展示字段不参与 token 验证（同改用户名的理由）。
- 仓储：`UserRepository::update_profile(id, patch)` 一条 UPDATE（只更新
  Some 的列），PG 实现动态拼 SET，测试桩同步实现。

### 4.1 API（gateway_api/routes/users_me.rs）

```
PATCH /api/users/me/profile
  body: { "display_name": "Loka", "bio": "rust & android", "website_url": null }
  → 200 { id, username, email, email_verified, display_name, avatar_url, bio, website_url, ... }
```

- PATCH 语义（部分更新），与 PUT /me/password、PUT /me/username 的「整体替换单字段」区分。
- `null` 显式清空字段；缺省字段不动。
- GET /api/users/me 响应同步加这 4 个字段（MeResponse 扩展）。
- 改头像支持「直接贴 URL」即可满足 GitHub 同步场景；上传自有头像
  （对象存储）列为明确不做，等有真实需求再评估。

### 4.2 平台资料选择 API（依托 raw_profile，可后置）

规范字段存好后，用户理论上可以从任一已绑定平台的 raw_profile 取值回填。
**本期不做专用 API**——PATCH /me/profile 已能完成同样的事（前端从
`GET /me/identities` 读 raw_profile 映射字段后提交 PATCH）。将来若做
「一键换用某平台头像」，再加 `POST /api/users/me/profile/apply {provider}`。

### 4.3 解绑身份 API（#5，一并纳入本期）

解绑的仓储方法已预留（`OauthIdentityRepository::remove`），补齐业务用例与路由：

```
DELETE /api/users/me/identities/{provider}
```

安全规则（业务层强制）：
- 解绑前检查用户剩余登录方式：密码已设（password_hash.is_some()）或还有
  其他身份绑定 → 允许；否则拒绝（400 "cannot unbind the last login method"）。
- `provider = "magic"` 特殊：解绑 magic 意味着放弃该邮箱的免密登录，
  同样受上述规则约束。
- 解绑后审计 `AuditAction::IdentityUnlinked`（detail 含 provider）。
- **不吊销会话**：已签发的 token 仍有效（解绑只影响"以后用该平台登录"）；
  若担心被盗号场景，用户可改密码（会吊销全部会话）或找 admin 强制下线。
- raw_profile 随身份行一起删除（CASCADE 已有）。

### 4.4 身份列表 API（配合解绑与资料选择）

```
GET /api/users/me/identities
  → 200 [{ provider, email, has_raw_profile, created_at }, ...]
```

- 给设置页展示「已绑定平台」；raw_profile 原文不直接暴露（体积大且含
  平台内部字段），只报 has_raw_profile 供前端判断是否可做「换用该平台头像」。
- 将来做「平台资料选择」时再扩展返回映射后的字段。

## 5. 改动面清单（实施时）

| 层 | 文件 | 改动 |
|----|------|------|
| 迁移 | migrations/0009_add_profile.sql | users 加 4 列 + user_identities 加 raw_profile（纯增量） |
| 业务层 | domain.rs | User/NewUser + 4 个 Option 字段 |
| 业务层 | oauth_identity.rs | ExternalProfile struct（含 raw）+ ExternalIdentity 加 raw_profile 字段 |
| 业务层 | service.rs | login_with_identity 签名 + 回填逻辑 + update_profile + 用户名生成优化 + unbind_identity 用例 |
| 业务层 | repository.rs | UserRepository::update_profile |
| 业务层 | audit.rs | ProfileUpdated + IdentityUnlinked |
| 存储层 | storage_pg/repository.rs | 行映射 + update_profile 动态 UPDATE + login 用例参数透传 |
| 存储层 | storage_pg/oauth_identities.rs | raw_profile 读写 + 身份查询带出 |
| 存储层 | .sqlx | cargo sqlx prepare 刷新 |
| 表现层 | routes/oauth.rs | GithubUser 扩展 + ExternalProfile 打包（raw = 裁剪后的 JSON） |
| 表现层 | routes/users_me.rs | MeResponse 扩展 + PATCH /me/profile + GET/DELETE /me/identities |
| 表现层 | routes/mod.rs | 挂载 PATCH/GET/DELETE 路由 |
| 测试 | service.rs | 资料回填不覆盖、update_profile 校验、PATCH 语义、解绑守门规则 |
| 文档 | AUTH_V2.md / README | P6-2 状态更新 |

## 6. 明确不做（本期）

- 头像/文件上传（对象存储、图片处理）——只支持 URL
- 平台资料变更的主动拉取/定时刷新——只在登录时刷新 raw_profile + 回填空缺
- Google/Apple 等 provider 的资料适配——先 GitHub 一家跑通，trait 已预留
- 「一键换用某平台资料」专用 API——PATCH /me/profile 已覆盖，见 §4.2
- 用户搜索/公开主页（需要 display_name 的检索索引）——等有产品形态再说
