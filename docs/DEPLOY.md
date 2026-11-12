# Rovortex 部署指南（方案 A：本地构建 → 传输上云）

> 目标服务器：cloud-01（45.76.71.93，Vultr，Debian 13，1C1G，已装 Docker 29.9.3 + Compose 插件）
>
> 核心思路：**编译只发生在本地**，服务器只收现成镜像、只跑容器。
> 服务器不需要 Rust 工具链、sqlx-cli，迁移 SQL 已编译期嵌入二进制。

## 全景图

```
┌─ 本地（Windows）────────────────┐   ┌─ 云服务器（cloud-01）─────────┐
│ 1. 改代码                        │   │ 5. docker load 导入镜像        │
│ 2. 生成/更新 .sqlx 离线缓存       │   │ 6. 写 .env（真实密码）          │
│ 3. 本地 docker compose 验证      │   │ 7. docker compose up --no-build│
│ 4. docker save 导出镜像 → scp    │ ──▶│ 8. curl 验证 /health、注册登录  │
└─────────────────────────────────┘   └────────────────────────────────┘
```

## 一次性准备（已完成）

- [x] `.sqlx/` 离线缓存生成并提交（`cargo sqlx prepare --workspace`，本地 PG 需在跑）
- [x] `migrations/` 建立，`state.rs` 启动时 `sqlx::migrate!` 自动执行
- [x] cloud-01 安装 Docker（apt 源 download.docker.com/linux/debian trixie）
- [x] 服务器目录 `/srv/rovortex`（含 docker-compose.yml、deploy.sh、.env）
- [x] SSH 免密（`~/.ssh/id_rsa` → 服务器 root）

## 标准流程（9 步详解）

### 第 1 步：改代码，确认能编译

```bash
cargo build --workspace        # 开发编译（快）
cargo test --workspace         # 跑测试
```

### 第 2 步：更新 .sqlx 离线缓存（仅当 SQL 变了）

**机制**：`query_as!` 宏在编译期校验 SQL 类型/列名，结果存 `.sqlx/`（每条 SQL 一个 JSON）。
Docker 构建无数据库可连，靠 `SQLX_OFFLINE=true` 读缓存完成校验，所以缓存必须进 git。

前提：本地 PG 在跑（`docker-compose.override.yml` 映射了 127.0.0.1:5432）。

```bash
docker compose up -d pg        # 确保数据库起着

DBPW=$(grep '^DB_PASSWORD=' .env | cut -d= -f2-)
DATABASE_URL="postgres://rovortex:${DBPW}@localhost:5432/rovortex" cargo sqlx prepare --workspace
# 成功输出：query data written to .sqlx in the workspace root
```

坑：全新数据库（刚 down -v）必须先有表才能校验——跑一次应用让它自动迁移，或手工执行迁移 SQL。

### 第 3 步：本地 Docker 全流程验证

```bash
docker compose build           # 首次约 10 分钟，之后有层缓存 1-2 分钟
docker compose up -d           # migrate 启动时自动执行，无需手动建表

# 三连验证
docker compose ps                                # 两个容器 Up，pg healthy
docker compose logs rovortex --tail 20           # 无 panic，listening on
curl http://localhost:8080/health                # {"status":"ok"}
curl -X POST http://localhost:8080/api/users/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"t1","email":"t1@e.com","password":"Str0ng-pass!"}'
```

镜像内发生什么：`rust:1-slim` 里 `cargo build --release`，产物（单二进制
`rovortex-gateway-api`）拷进 `debian:bookworm-slim`（最终 138MB）。
迁移 SQL 被 `migrate!` 宏在编译期嵌入二进制，运行时不需要源码。

常见报错：

| 报错 | 原因 | 处理 |
|------|------|------|
| 构建：canonicalizing migration directory ... No such file | Dockerfile 没拷 migrations | Dockerfile 加 `COPY migrations migrations` |
| 构建：宏校验失败 / error communicating with database | `.sqlx` 过期或缺失 | 回第 2 步重新 prepare |
| 启动：relation "users" already exists | 库里有手工建的表但无迁移记录 | `docker compose down -v` 删卷重来 |
| 本地起应用连不上库 | 本地 override 没起，5432 没映射 | `docker compose up -d pg` |

### 第 4 步：导出镜像，传到服务器

```bash
# 应用 138MB + PG 420MB，压缩后约 143MB；PG 镜像第二次起不用重传
docker save rovortex-rovortex:latest postgres:16-alpine | gzip > rovortex-images.tar.gz

ssh root@45.76.71.93 "mkdir -p /srv/rovortex"   # 首次才需要
scp rovortex-images.tar.gz docker-compose.yml deploy.sh root@45.76.71.93:/srv/rovortex/

rm rovortex-images.tar.gz       # 传完删本地包
```

### 第 5 步：服务器导入镜像

```bash
ssh root@45.76.71.93
cd /srv/rovortex
docker load -i rovortex-images.tar.gz
docker images    # 确认 rovortex-rovortex:latest、postgres:16-alpine
```

### 第 6 步：服务器配置 .env

```bash
printf 'DB_PASSWORD=你的强密码\n' > .env
chmod 600 .env
```

- compose 里 `ROVORTEX_DB_URL: postgres://rovortex:${DB_PASSWORD}@pg:5432/rovortex` 自动注入
- PG 容器**首次启动**用它初始化密码；之后改密码须进库 ALTER USER，光改 .env 无效
- 服务器上**不要**有 docker-compose.override.yml（会把 5432 暴露公网）

### 第 7 步：启动

```bash
docker compose up -d --no-build
```

`--no-build`：服务器无源码，只用本地已导入镜像，缺了报错而不是尝试构建。
启动顺序由 `depends_on: condition: service_healthy` 保证：
pg 起且健康检查通过 → 应用启动 → 自动跑迁移建表。

### 第 8 步：验证

```bash
# 服务器上
curl http://localhost:8080/health
docker compose logs rovortex | grep -i listen

# 本地（验证公网可达）
curl http://45.76.71.93:8080/health
```

### 第 9 步：日常迭代（第二次以后）

```bash
# 本地
docker compose build
docker save rovortex-rovortex:latest | gzip > rovortex-app.tar.gz
scp rovortex-app.tar.gz root@45.76.71.93:/srv/rovortex/

# 服务器
cd /srv/rovortex
docker load -i rovortex-app.tar.gz
docker compose up -d --no-build   # compose 检测镜像变化，只重建应用容器
```

数据在 `pgdata` 卷里，应用容器重建不影响；PG 镜像没变不用重传。
注意：`up -d` 替换容器瞬间有几秒不可用（无就绪探针），量大了再加 healthcheck 做零停机。

## 服务器常用运维命令

```bash
cd /srv/rovortex
docker compose ps                  # 容器状态
docker compose logs -f rovortex    # 跟踪应用日志
docker compose restart rovortex    # 重启应用
docker compose down                # 停全部（数据卷保留）
docker compose down -v             # 停全部并删数据卷（危险：清库）
docker system df                   # 磁盘占用
docker image prune -a              # 清理无用镜像（磁盘紧张时）
```

## 已知限制 / 后续待办

- [ ] 8080 裸 HTTP 直暴露公网，需加反代 + TLS（Caddy 最省事，自动申请证书）
- [ ] `.env` 里是临时密码 `RovortexT3mp!2026`，需换正式强密码
- [ ] 无零停机部署（替换容器有几秒中断）
- [ ] 单机部署无自动恢复（容器崩了靠 restart: unless-stopped，机器挂了要手动）

## 什么时候升级到方案 B（CI/CD 或镜像仓库）

出现以下任一情况：多台服务器、发布频繁、需要回滚（tag 版本号 + 仓库保留旧版本）。
见下方 GitHub Actions 相关章节。

---

# GitHub Actions CI/CD（方案 B：云上构建/推送，自动部署）

> 前提：rovortex 在 GitHub 已有仓库。此方案下**本地完全不需要参与构建**，
> push 代码 → GitHub 云上构建镜像 → 推到 GHCR → SSH 到服务器拉取重启。

## 架构

```
┌─ 本地 ────────┐   ┌─ GitHub ──────────────────────┐   ┌─ cloud-01 ─────────┐
│ git push      │ ─▶│ Actions: cargo test            │   │ 拉镜像              │
│               │   │          docker build + push   │ ─▶ │ docker compose up  │
└───────────────┘   │ (推到 ghcr.io/<user>/rovortex) │   └─────────────────────┘
                    └────────────────────────────────┘
```

优势：本地不编译不传输；每次 push 自动测试+部署；可回滚（镜像按 git sha 打 tag）。
代价：服务器需要能拉 ghcr.io（Vultr 在国外，没问题）；GitHub 免费额度对公共仓库无限、
私有仓库每月 2000 分钟（本次构建约 10 分钟/次，个人项目够用）。

## 一次性设置

### 0. GHCR 包可见性（重要坑）

仓库转 public **不会**自动把已存在的 GHCR 包转 public（包默认继承创建时的仓库状态）。
private 包服务器匿名 pull 会 401。处理：
- **public 仓库**：包页面 → Package settings → Danger Zone → Change visibility → Public，
  服务器匿名拉取，workflow 无需额外令牌（推镜像用自带 GITHUB_TOKEN）。
- **private 仓库**：需给服务器发 read:packages PAT 加 secret，且每月仅 1GB 免费拉取流量。

包页：https://github.com/<user>/packages/container/package/<包名>

### 1. 服务器生成部署密钥对（用于 GitHub 回连）

```bash
ssh root@45.76.71.93
ssh-keygen -t ed25519 -f ~/.ssh/deploy_key -N "" -C "github-actions-deploy"
cat ~/.ssh/deploy_key.pub >> ~/.ssh/authorized_keys
cat ~/.ssh/deploy_key     # 私钥内容，下一步要用
```

### 2. GitHub 仓库配 Secrets（Settings → Secrets and variables → Actions）

| Secret 名 | 值 |
|-----------|-----|
| `DEPLOY_SSH_KEY` | 上面 deploy_key 私钥全文（-----BEGIN 到 -----END） |
| `DEPLOY_HOST` | `45.76.71.93` |
| `DEPLOY_USER` | `root` |

无需配 GHCR 令牌：Actions 内用 `GITHUB_TOKEN`（自动提供）推 GHCR。

### 3. 添加 workflow 文件 `.github/workflows/deploy.yml`

```yaml
name: deploy

on:
  push:
    branches: [master]

jobs:
  test-build-deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4

      - name: Run tests
        run: cargo test --workspace

      - name: Set image tag
        id: tag
        run: echo "sha=${GITHUB_SHA::8}" >> "$GITHUB_OUTPUT"

      - name: Build and push image
        uses: docker/build-push-action@v6
        with:
          context: .
          file: crates/gateway_api/Dockerfile
          push: true
          tags: |
            ghcr.io/${{ github.repository_owner }}/rovortex-api:latest
            ghcr.io/${{ github.repository_owner }}/rovortex-api:${{ steps.tag.outputs.sha }}
          # .sqlx 已在仓库中，SQLX_OFFLINE=true 在 Dockerfile 里，无需额外准备

      - name: Deploy to cloud-01
        uses: appleboy/ssh-action@v1
        with:
          host: ${{ secrets.DEPLOY_HOST }}
          username: ${{ secrets.DEPLOY_USER }}
          key: ${{ secrets.DEPLOY_SSH_KEY }}
          script: |
            docker pull ghcr.io/${{ github.repository_owner }}/rovortex-api:${{ steps.tag.outputs.sha }}
            docker tag ghcr.io/${{ github.repository_owner }}/rovortex-api:${{ steps.tag.outputs.sha }} rovortex-rovortex:latest
            cd /srv/rovortex && docker compose up -d --no-build
            docker image prune -f
```

### 4. 服务器 compose 切换到镜像仓库模式

服务器上 `/srv/rovortex/docker-compose.yml` 把 `build:` 段换成 `image:`：

```yaml
  rovortex:
    image: rovortex-rovortex:latest   # 由 deploy 脚本 pull + retag，本地镜像名不变
    # build:
    #   context: .
    #   dockerfile: crates/gateway_api/Dockerfile
```

（或直接 `image: ghcr.io/<user>/rovortex-api:latest`，则 deploy 步骤里 tag 那行可省。）

### 5. 首次验证

```bash
git add .github/workflows/deploy.yml && git commit -m "ci: add deploy workflow" && git push
# GitHub 仓库页 → Actions 标签页看进度（约 10 分钟）
# 成功后验证
curl http://45.76.71.93:8080/health
```

## 回滚

```bash
# Actions 每次构建都推了带 git sha 的 tag，回滚 = 部署旧 tag
ssh root@45.76.71.93
docker pull ghcr.io/<user>/rovortex-api:<旧sha>
docker tag ghcr.io/<user>/rovortex-api:<旧sha> rovortex-rovortex:latest
cd /srv/rovortex && docker compose up -d --no-build
```

## 两方案对比

| | 方案 A（当前，本地构建） | 方案 B（GitHub Actions） |
|---|---|---|
| 编译位置 | 本地 PC | GitHub 云端 |
| 部署触发 | 手动跑命令 | git push 自动 |
| 传输内容 | 143MB tar 包 scp | 服务器直接 pull（增量层） |
| 回滚 | 留着旧 tar 包，麻烦 | 按镜像 tag 秒回滚 |
| 依赖 | 本地 Docker + SSH | GitHub 免费额度、服务器可出网拉 ghcr |
| 适合 | 当前单机、低频发布 | 团队协作、频繁迭代、需回滚 |
