# ---- 构建阶段 ----
FROM rust:1.99-slim AS builder

WORKDIR /app

# 复制 Cargo 清单，复用 cargo 缓存（加快后续构建）
COPY Cargo.toml Cargo.lock ./
COPY crates crates

# 必须先生成 sqlx-data.json 再 build（见下方说明）
# 若已有 sqlx-data.json，取消下面注释：
# COPY sqlx-data.json ./

# 编译：--release + --locked，保证可复现
RUN cargo build --release --locked

# ---- 运行阶段 ----
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/rovortex-gateway-api /usr/local/bin/

EXPOSE 8080

CMD ["rovortex-gateway-api"]
