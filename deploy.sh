#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "==> 1. 确认 Docker 与 Docker Compose 可用"
docker --version
docker compose version

echo "==> 2. 复制环境变量模板"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "    已生成 .env，请编辑 .env 填写密码等配置。"
else
  echo "    已存在 .env，跳过。"
fi

echo "==> 3. 生成 sqlx-data.json（sqlx 编译期校验需要）"
if [ ! -f sqlx-data.json ]; then
  echo "    未找到 sqlx-data.json，正在生成..."
  DATABASE_URL="${ROVORTEX_DB_URL:-postgres://rovortex:***@localhost:5432/rovortex}" \
  cargo sqlx prepare --workspace --locked
  echo "    已生成 sqlx-data.json。"
else
  echo "    已有 sqlx-data.json，跳过。"
fi

echo "==> 4. 构建并启动容器"
docker compose up -d --build

echo "==> 5. 查看状态"
docker compose ps
echo "==> 6. 查看日志"
docker compose logs -f
