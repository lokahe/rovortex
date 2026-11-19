-- 用户资料体系（P6-2）：users 规范字段 + user_identities 平台原始资料缓存。
-- 纯增量迁移：全部可空，存量用户无感。

-- 规范字段（前端展示层读取的唯一来源；可空 = 前端 fallback username/默认头像）
ALTER TABLE users
    ADD COLUMN display_name TEXT,
    ADD COLUMN avatar_url   TEXT,
    ADD COLUMN bio          TEXT,
    ADD COLUMN website_url  TEXT;

-- 各平台原始资料（key 由 provider 决定，JSONB；登录时刷新，解绑随行删除）
ALTER TABLE user_identities
    ADD COLUMN raw_profile JSONB;
