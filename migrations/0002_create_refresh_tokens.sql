-- refresh tokens：登录后签发，用于换取新 access token。
-- token 以 SHA-256 哈希落库（库泄露不能直接冒用）；显式吊销用于登出与改密码后失效。
CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 登录/刷新时按 token 哈希精确查找
CREATE UNIQUE INDEX refresh_tokens_token_hash_uniq ON refresh_tokens (token_hash);
-- 吊销某用户的全部有效 token（改密码、封禁）
CREATE INDEX refresh_tokens_user_id_idx ON refresh_tokens (user_id);
-- 清理过期行（定期任务或手动）
CREATE INDEX refresh_tokens_expires_at_idx ON refresh_tokens (expires_at);
