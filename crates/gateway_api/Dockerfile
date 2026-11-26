# ---- admin SPA 构建阶段（rust-embed 编译期需要 dist 存在）----
FROM node:20-slim AS web-builder

WORKDIR /web
COPY web/admin/package.json web/admin/package-lock.json ./
RUN npm ci

COPY web/admin/ ./
RUN npm run build    # 产出 /web/dist（vite base=/admin/）

# ---- Rust 构建阶段 ----
FROM rust:1-slim AS builder

WORKDIR /app

# 先复制清单以复用依赖缓存层
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY migrations migrations

# .sqlx 离线缓存由 cargo sqlx prepare 在本地生成并随上下文复制
COPY .sqlx ./.sqlx
ENV SQLX_OFFLINE=true

# admin SPA 产物（rust-embed folder 编译期读取；dist 缺失会编译失败，属预期）
COPY --from=web-builder /web/dist /app/web/admin/dist
ENV ROVORTEX_ADMIN_DIST=/app/web/admin/dist

RUN cargo build --release --locked --package rovortex-gateway-api

# ---- 运行阶段 ----
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 迁移脚本随镜像携带，启动时由 sqlx::migrate! 内嵌执行（实际是编译期嵌入）
COPY --from=builder /app/target/release/rovortex-gateway-api /usr/local/bin/

EXPOSE 8080

CMD ["rovortex-gateway-api"]
