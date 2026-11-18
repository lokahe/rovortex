-- 邮箱验证状态标记。存量用户默认 false（注册邮件逐个重发触发验证）。
ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT false;
