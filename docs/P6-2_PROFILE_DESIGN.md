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
}

login_with_identity(provider, uid, email, profile: Option<ExternalProfile>, ip)
```

业务层不出现 "github" 字眼——延续 AUTH_V2.md §4 的「协议细节不进业务层」。

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

## 5. 改动面清单（实施时）

| 层 | 文件 | 改动 |
|----|------|------|
| 迁移 | migrations/0009_add_profile.sql | 新增 4 列（纯增量） |
| 业务层 | domain.rs | User/NewUser + 4 个 Option 字段 |
| 业务层 | oauth_identity.rs | ExternalProfile struct |
| 业务层 | service.rs | login_with_identity 签名 + 回填逻辑 + update_profile + 用户名生成优化 |
| 业务层 | repository.rs | UserRepository::update_profile |
| 业务层 | audit.rs | ProfileUpdated |
| 存储层 | storage_pg/repository.rs | 行映射 + update_profile 动态 UPDATE + login 用例参数透传 |
| 存储层 | .sqlx | cargo sqlx prepare 刷新 |
| 表现层 | routes/oauth.rs | GithubUser 扩展 + ExternalProfile 打包 |
| 表现层 | routes/users_me.rs | MeResponse 扩展 + PATCH /me/profile |
| 表现层 | routes/mod.rs | 挂载 PATCH 路由 |
| 测试 | service.rs | 资料回填不覆盖、update_profile 校验、PATCH 语义 |
| 文档 | AUTH_V2.md / README | P6-2 状态更新 |

## 6. 明确不做（本期）

- 头像/文件上传（对象存储、图片处理）——只支持 URL
- 平台资料变更的主动拉取/定时刷新——只在登录时回填空缺
- Google/Apple 等 provider 的资料适配——先 GitHub 一家跑通，trait 已预留
- 用户搜索/公开主页（需要 display_name 的检索索引）——等有产品形态再说
