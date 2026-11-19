-- 账号注销（软删 + 冷静期，#6）。
-- status: 0=正常 1=封禁 2=已注销（软删）。注销账号登录时被挡，冷静期内可恢复。
-- email 被挪到 deleted-<uuid>@deleted.invalid 释放原邮箱给新注册；
-- user_identities 由 FK CASCADE 删除；audit_logs SET NULL 自动匿名。
ALTER TABLE users
    ADD COLUMN deleted_at TIMESTAMPTZ;

-- 到期硬删的批量查询（cron，P7 范畴）
CREATE INDEX users_deleted_at_idx ON users (deleted_at)
    WHERE status = 2;
