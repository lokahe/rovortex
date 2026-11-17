-- 外部身份表：OAuth / Magic Link 的「平台侧身份 → 本地账号」映射。
-- UNIQUE(provider, provider_uid) 是登录查找主键：回调拿到 (provider, uid) 后
-- 一条 SELECT 判断「老用户直接登录 / 新用户自动注册」。
CREATE TABLE user_identities (
    id           UUID PRIMARY KEY,
    user_id      UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider     TEXT        NOT NULL,   -- 'github' | 'google' | 'magic' ...
    provider_uid TEXT        NOT NULL,   -- 平台侧唯一 id；magic 时为邮箱本身
    email        TEXT,                   -- 平台报告的邮箱（可能为空）
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, provider_uid)
);

CREATE INDEX user_identities_user_id_idx ON user_identities (user_id);
