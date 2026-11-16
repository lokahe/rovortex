-- 邮箱验证：一次性 token（哈希落库），支持注册验证与改邮箱两种用途。
CREATE TABLE email_verifications (
    id          UUID PRIMARY KEY,
    email       TEXT        NOT NULL,
    token_hash  TEXT        NOT NULL,
    purpose     TEXT        NOT NULL,              -- 'signup' | 'email_change'
    user_id     UUID        REFERENCES users(id) ON DELETE CASCADE,  -- email_change 时必填
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX email_verifications_token_hash_uniq ON email_verifications (token_hash);
-- 清理过期行
CREATE INDEX email_verifications_expires_at_idx ON email_verifications (expires_at);
