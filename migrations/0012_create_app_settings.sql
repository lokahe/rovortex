-- 运行期键值设置（任务开关、可调参数）——SharedPreferences 形态：
-- 进程内 RwLock 缓存 + 写穿到本表；重启时加载回缓存。改值无需重启。
CREATE TABLE app_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
