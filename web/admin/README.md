# rovortex-admin

rovortex 服务端的管理后台前端（独立工程），React 19 + Vite 5 + TypeScript + Ant Design 5。

后端对应 rovortex 仓库的 A1-A3 能力：管理员登录（`POST /api/users/login` + `is_admin` 校验）、Admin API（用户列表/详情/封禁/统计）、CORS 白名单。

## 开发

```bash
npm install
npm run dev        # http://localhost:5173
```

`.env.development`（或环境变量）配置后端地址：

```
VITE_API_BASE=http://localhost:8080
```

后端侧需要：

- `ROVORTEX_ADMIN_EMAILS=<你的邮箱>` —— 启动时自动把该邮箱提升为管理员
- `ROVORTEX_CORS_ORIGINS=http://localhost:5173` —— CORS 白名单，缺省全拒绝

## 构建

```bash
npm run build      # 产物在 dist/
npm run preview
```

## 页面

- `/login` — 管理员账号密码登录（该账号必须是 `is_admin = true` 的用户）
- `/` — 仪表盘：近 7 天注册/登录事件统计（`GET /api/admin/stats`）
- `/users` — 用户管理：搜索、分页、封禁/解封、详情抽屉（OAuth/Magic 身份 + 审计日志）

## 认证机制

- access/refresh token 存 `localStorage`（key：`rovortex_admin_access` / `rovortex_admin_refresh`）
- axios 拦截器：请求带 `Authorization: Bearer`；遇 401 自动用 refresh token 换新并重放原请求（single-flight），失败则跳转 `/login`
- 服务端每个请求实时查库校验 `is_admin`，封禁/取消管理员立即生效（无 token 缓存窗口）

## 注意

- CORS 白名单基于 `Origin` 精确匹配，生产部署时需把正式域名加进 `ROVORTEX_CORS_ORIGINS`
- Vite 固定 5.x：本机 Node 20.15 不满足 Vite 8 的 ^20.19 要求（rolldown 原生绑定加载失败）
