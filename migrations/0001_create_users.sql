-- users 表：UUIDv7 主键（应用侧生成），GENERATED 列实现大小写不敏感唯一性
CREATE TABLE users (
    id            UUID PRIMARY KEY,
    username      TEXT        NOT NULL,
    username_key  TEXT        NOT NULL GENERATED ALWAYS AS (lower(username)) STORED,
    email         TEXT        NOT NULL,
    email_key     TEXT        NOT NULL GENERATED ALWAYS AS (lower(email)) STORED,
    password_hash TEXT        NOT NULL,
    status        SMALLINT    NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX users_username_uniq ON users (username_key);
CREATE UNIQUE INDEX users_email_uniq    ON users (email_key);
CREATE INDEX users_created_at_idx ON users (created_at);
