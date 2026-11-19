-- 会话列表 / 踢设备（#8）：refresh_tokens 补设备描述。
-- 隐私边界：只存 UA 解析结果（设备·OS·浏览器）与粗粒度 IP（前两段 /16 级），
-- 不存原始 UA、不存完整 IP；设备标签仅用于"人认设备"，不是安全边界
-- （真·安全靠 refresh token 轮换与哈希落库，已有）。
ALTER TABLE refresh_tokens
    ADD COLUMN device_label TEXT,
    ADD COLUMN ua           TEXT,
    ADD COLUMN ip_last      TEXT,
    ADD COLUMN last_used_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- 会话列表按用户查询（过期行的过滤由查询承担：索引谓词要求 IMMUTABLE，不能写 now()）
CREATE INDEX refresh_tokens_user_active_idx
    ON refresh_tokens (user_id)
    WHERE revoked_at IS NULL;
