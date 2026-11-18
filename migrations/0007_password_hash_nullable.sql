-- OAuth / Magic Link 用户没有密码：password_hash 可空化（纯增量，存量行不受影响）。
-- 语义由业务层强制：password_hash IS NULL 的账号密码登录一律 InvalidCredentials（防枚举）。
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
