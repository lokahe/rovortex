-- 管理员标记：admin API 的授权依据。
-- 首个 admin 由 ROVORTEX_ADMIN_EMAILS 启动提升（组合根），不走注册接口。
ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX users_is_admin_idx ON users (is_admin) WHERE is_admin;
