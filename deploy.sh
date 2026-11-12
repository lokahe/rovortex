#!/usr/bin/env bash
# 在云服务器上使用：拉取仓库后直接 docker compose up -d --build。
# 前提：服务器上已存在 .env（含 DB_PASSWORD），仓库里已有 .sqlx 离线缓存（随 git 提交）。
set -euo pipefail

cd "$(dirname "$0")"

echo "==> 1. 确认 Docker 与 Docker Compose 可用"
docker --version
docker compose version

if [ ! -f .env ]; then
  echo "错误：缺少 .env，请先创建（参考 .env.example，填写真实 DB_PASSWORD）" >&2
  exit 1
fi

echo "==> 2. 构建并启动容器"
docker compose up -d --build

echo "==> 3. 查看状态"
docker compose ps
echo "==> 4. 查看日志"
docker compose logs -f
