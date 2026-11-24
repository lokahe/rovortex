//! 管理端服务配置（.env）查看与编辑。
//!
//! 容器把宿主机 `/srv/rovortex` 以 rw 挂到 `/app/config`（docker-compose.yml），
//! `.env` 即 `/app/config/.env`。GET 解析展示，PUT 整体写回 + 写审计。
//! 生效仍需重启容器：重启接口单独走 docker.sock（restart_container）。
//!
//! 安全边界：仅 require_admin 可达；secret 值 GET 时脱敏，
//! PUT 时「仍为脱敏占位符」的 secret 字段保留原值不覆盖。

use std::collections::BTreeMap;
use std::path::PathBuf;

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::routes::auth::AdminUser;
use crate::state::AppState;
use rovortex_users::audit::{AuditAction, NewAuditLog};

/// 宿主机 .env 在容器内的挂载路径。
const ENV_FILE: &str = "/app/config/.env";
/// compose 里 ${VAR} 引用、但只该由宿主层掌握的键：不展示也不可改。
const HIDDEN_KEYS: &[&str] = &["DB_PASSWORD"];

/// GET 时脱敏的 secret 键：值替换为占位符。
const SECRET_KEYS: &[&str] = &[
    "ROVORTEX_JWT_SECRET",
    "RESEND_API_KEY",
    "OAUTH_GITHUB_CLIENT_SECRET",
    "OAUTH_GOOGLE_CLIENT_SECRET",
];
/// 脱敏占位符；PUT 回传该值 = 用户没改，保留磁盘原值。
pub const REDACTED: &str = "••••••••（未修改）";

/// 已知配置键的说明（前端展示用）；未知键仍展示但说明为空。
pub const KEY_DOCS: &[(&str, &str)] = &[
    ("ROVORTEX_JWT_SECRET", "JWT HS256 签名密钥。改了所有已登录 token 立即失效"),
    ("RESEND_API_KEY", "Resend 发信 API key（re_ 开头）"),
    ("ROVORTEX_MAIL_FROM", "发件人地址，如 noreply@lokahe.top"),
    ("ROVORTEX_VERIFY_URL_BASE", "验证邮件确认链接前缀"),
    ("OAUTH_GITHUB_CLIENT_ID", "GitHub OAuth App Client ID"),
    ("OAUTH_GITHUB_CLIENT_SECRET", "GitHub OAuth App Client Secret"),
    ("OAUTH_GOOGLE_CLIENT_ID", "Google OAuth Client ID"),
    ("OAUTH_GOOGLE_CLIENT_SECRET", "Google OAuth Client Secret"),
    ("ROVORTEX_ADMIN_EMAILS", "管理员邮箱名单（逗号分隔；启动时提升 is_admin）"),
    ("ROVORTEX_CORS_ORIGINS", "跨域允许来源（逗号分隔；空 = 拒绝所有跨域）"),
    ("ROVORTEX_LOGIN_MAX_FAILURES", "登录失败锁定阈值（次）"),
    ("ROVORTEX_LOGIN_LOCK_WINDOW_SECS", "登录锁定时长（秒）"),
    ("ROVORTEX_MAIL_MIN_INTERVAL_SECS", "同类邮件最小间隔（秒）"),
    ("ROVORTEX_MAIL_HOURLY_LIMIT", "每小时邮件上限（封）"),
    ("ROVORTEX_MAIL_HOURLY_WINDOW_SECS", "每小时限额窗口（秒）"),
    ("ROVORTEX_LOG_BUFFER_CAPACITY", "内存日志环形缓冲条数"),
    ("ROVORTEX_REFRESH_TTL_DAYS", "refresh token 有效期（天）"),
    ("ROVORTEX_EMAIL_VERIFICATION_TTL_MINS", "验证链接/验证码有效期（分钟）"),
    ("ROVORTEX_DELETION_GRACE_DAYS", "注销冷静期（天）"),
    ("ROVORTEX_PASSWORD_MIN_LENGTH", "密码最小长度"),
    ("ROVORTEX_PASSWORD_MAX_LENGTH", "密码最大长度"),
    ("EMAIL_CHANNEL_CODE", "验证邮件含验证码：1 开 0 关"),
    ("EMAIL_CHANNEL_PC_LINK", "验证邮件含网页链接：1 开 0 关"),
    ("EMAIL_CHANNEL_APP_LINK", "验证邮件含 App 深链：1 开 0 关"),
    ("EMAIL_APP_LINK_SCHEME", "App 深链 scheme（如 rovortex）"),
];

#[derive(Debug, Serialize)]
pub struct ConfigEntry {
    pub key: String,
    /// 脱敏后的值；secret 键为占位符。
    pub value: String,
    /// 是否 secret（脱敏展示）。
    pub secret: bool,
    pub doc: String,
    /// 该键是否被 compose 透传给容器（没透传的改了也不生效）。
    pub wired: bool,
}

#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    /// .env 文件里实际有的键（K-V，脱敏后）。
    pub entries: Vec<ConfigEntry>,
    /// 容器已知的全部可透传键（含 .env 里还没配的），前端补全输入建议。
    pub available_keys: Vec<String>,
    /// .env 文件最后修改时间（RFC3339）。
    pub modified_at: Option<String>,
}

/// compose 透传给容器的键（与 docker-compose.yml environment 对齐）。
const WIRED_KEYS: &[&str] = &[
    "ROVORTEX_JWT_SECRET",
    "RESEND_API_KEY",
    "ROVORTEX_MAIL_FROM",
    "ROVORTEX_VERIFY_URL_BASE",
    "OAUTH_GITHUB_CLIENT_ID",
    "OAUTH_GITHUB_CLIENT_SECRET",
    "OAUTH_GOOGLE_CLIENT_ID",
    "OAUTH_GOOGLE_CLIENT_SECRET",
    "ROVORTEX_ADMIN_EMAILS",
    "ROVORTEX_CORS_ORIGINS",
    "ROVORTEX_LOGIN_MAX_FAILURES",
    "ROVORTEX_LOGIN_LOCK_WINDOW_SECS",
    "ROVORTEX_MAIL_MIN_INTERVAL_SECS",
    "ROVORTEX_MAIL_HOURLY_LIMIT",
    "ROVORTEX_MAIL_HOURLY_WINDOW_SECS",
    "ROVORTEX_LOG_BUFFER_CAPACITY",
    "ROVORTEX_REFRESH_TTL_DAYS",
    "ROVORTEX_EMAIL_VERIFICATION_TTL_MINS",
    "ROVORTEX_DELETION_GRACE_DAYS",
    "ROVORTEX_PASSWORD_MIN_LENGTH",
    "ROVORTEX_PASSWORD_MAX_LENGTH",
    "EMAIL_CHANNEL_CODE",
    "EMAIL_CHANNEL_PC_LINK",
    "EMAIL_CHANNEL_APP_LINK",
    "EMAIL_APP_LINK_SCHEME",
];

/// .env 在容器内的挂载路径；本地测试可用 ROVORTEX_ENV_FILE 覆盖。
fn env_path() -> PathBuf {
    std::env::var("ROVORTEX_ENV_FILE").unwrap_or_else(|_| ENV_FILE.to_string()).into()
}

/// 解析 .env 文本为有序 K-V（保留重复键的最后值；行注释跳过）。
/// 返回 (键值对, 原始行结构)，写回时按键重排，注释不保留（配置页管理一切）。
fn parse_env(text: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        map.insert(k.trim().to_string(), v.trim().to_string());
    }
    map
}

fn render_env(map: &BTreeMap<String, String>) -> String {
    let mut out = String::from("# rovortex 服务配置（admin 配置页维护；改完需重启容器生效）\n\n");
    for (k, v) in map {
        out.push_str(&format!("{k}={v}\n"));
    }
    out
}

/// GET /api/admin/config —— 读取 .env（secret 脱敏）。
pub async fn get_config(
    State(_state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<ConfigResponse>, ApiError> {
    let path = env_path();
    let text = std::fs::read_to_string(&path)
        .map_err(|e| ApiError::internal(format!("cannot read {ENV_FILE}: {e}")))?;
    let modified_at = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .ok()
        .map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.to_rfc3339()
        });

    let map = parse_env(&text);
    let mut entries = Vec::new();
    for (k, v) in &map {
        if HIDDEN_KEYS.contains(&k.as_str()) {
            continue;
        }
        let secret = SECRET_KEYS.contains(&k.as_str());
        let shown = if secret { REDACTED.to_string() } else { v.clone() };
        let doc = KEY_DOCS
            .iter()
            .find(|(dk, _)| *dk == k)
            .map(|(_, d)| d.to_string())
            .unwrap_or_default();
        entries.push(ConfigEntry {
            key: k.clone(),
            value: shown,
            secret,
            doc,
            wired: WIRED_KEYS.contains(&k.as_str()),
        });
    }
    // KEY_DOCS 里已透传但 .env 未配置的键：提示可添加。
    for (k, d) in KEY_DOCS {
        if map.contains_key(*k) || HIDDEN_KEYS.contains(k) {
            continue;
        }
        if WIRED_KEYS.contains(k)
            || k.starts_with("EMAIL_")
            || k.starts_with("ROVORTEX_")
        {
            entries.push(ConfigEntry {
                key: k.to_string(),
                value: String::new(),
                secret: SECRET_KEYS.contains(k),
                doc: d.to_string(),
                wired: WIRED_KEYS.contains(k),
            });
        }
    }

    let available_keys = KEY_DOCS.iter().map(|(k, _)| k.to_string()).collect();
    Ok(Json(ConfigResponse {
        entries,
        available_keys,
        modified_at,
    }))
}

#[derive(Debug, Deserialize)]
pub struct UpdateConfigRequest {
    /// key → 新值（secret 键传占位符 = 保留原值）。
    pub values: BTreeMap<String, String>,
}

/// 校验单条值的合法性（只挡格式明显错的，不做语义校验）。
fn validate_value(key: &str, value: &str) -> Result<(), ApiError> {
    if key.is_empty()
        || !key.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return Err(ApiError::bad_request(format!("invalid key: {key}")));
    }
    if value.contains('\n') || value.contains('\r') {
        return Err(ApiError::bad_request(format!("{key}: 值不能包含换行")));
    }
    // 数字型键必须是正整数。
    if key.starts_with("ROVORTEX_") && (key.contains("SECS") || key.contains("DAYS") || key.contains("MINS") || key.ends_with("_LENGTH") || key.ends_with("_LIMIT") || key.ends_with("_FAILURES") || key.ends_with("_CAPACITY")) {
        if value.parse::<u64>().is_err() {
            return Err(ApiError::bad_request(format!("{key}: 需要正整数")));
        }
    }
    if key == "EMAIL_CHANNEL_CODE" || key == "EMAIL_CHANNEL_PC_LINK" || key == "EMAIL_CHANNEL_APP_LINK" {
        if value != "0" && value != "1" {
            return Err(ApiError::bad_request(format!("{key}: 只能是 0 或 1")));
        }
    }
    Ok(())
}

/// PUT /api/admin/config —— 整体写回 .env + 审计。不重启；重启走 POST /restart。
pub async fn update_config(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<UpdateConfigRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let path = env_path();
    let old_text = std::fs::read_to_string(&path)
        .map_err(|e| ApiError::internal(format!("cannot read {ENV_FILE}: {e}")))?;
    let old_map = parse_env(&old_text);
    let mut map = old_map.clone();

    for (k, v) in &req.values {
        if HIDDEN_KEYS.contains(&k.as_str()) {
            return Err(ApiError::bad_request(format!("{k} 不可通过配置页修改")));
        }
        validate_value(k, v)?;
        if SECRET_KEYS.contains(&k.as_str()) && v == REDACTED {
            continue; // 占位符 = 未修改，保留磁盘值
        }
        map.insert(k.clone(), v.clone());
    }

    let new_text = render_env(&map);
    std::fs::write(&path, new_text)
        .map_err(|e| ApiError::internal(format!("cannot write {ENV_FILE}: {e}")))?;

    // 审计：变更的键名（secret 值不落审计）。与写盘前的旧值对比。
    let changed: Vec<String> = req
        .values
        .iter()
        .filter(|(k, v)| {
            !(SECRET_KEYS.contains(&k.as_str()) && v.as_str() == REDACTED)
                && old_map.get(*k).map(|old| old != *v).unwrap_or(true)
        })
        .map(|(k, _)| k.clone())
        .collect();
    let changed_keys = changed.join(",");
    let _ = state
        .audit
        .append(NewAuditLog {
            user_id: Some(admin.user_id),
            action: AuditAction::AdminConfigUpdate,
            detail: format!("keys={changed_keys}"),
            client_ip: String::new(),
        })
        .await;

    Ok(Json(serde_json::json!({ "updated": changed.len() })))
}

#[derive(Debug, Serialize)]
pub struct RestartResponse {
    pub restarted: bool,
}

/// POST /api/admin/config/restart —— 重启自身容器（docker.sock 挂载）。
/// 自身重启 = 请求方连接会断，前端要按「请求发出即成功」处理。
pub async fn restart_container(
    State(_state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<RestartResponse>, ApiError> {
    // HOSTNAME 环境变量由 docker 注入 = 本容器 id。
    let self_id = std::env::var("HOSTNAME").unwrap_or_default();
    if self_id.is_empty() {
        return Err(ApiError::internal("HOSTNAME not set (not in docker?)".into()));
    }
    // docker CLI 不在镜像里，直接 HTTP 打 docker.sock（API: POST /containers/{id}/restart）。
    // 阻塞 IO 扔 blocking 线程；Windows 本地构建时走 stub（生产只在 Linux 容器跑）。
    #[cfg(unix)]
    let restart = tokio::task::spawn_blocking(move || docker_sock_restart("/var/run/docker.sock", &self_id))
        .await
        .map_err(|e| ApiError::internal(format!("restart task failed: {e}")))?;
    #[cfg(not(unix))]
    let restart: Result<(), ApiError> = Err(ApiError::internal(
        "docker.sock restart only works on Linux (server) builds".into(),
    ));
    restart.map(|_| Json(RestartResponse { restarted: true }))
}

/// 裸 HTTP over Unix socket 调 docker API 重启容器。
#[cfg(unix)]
fn docker_sock_restart(sock_path: &str, container_id: &str) -> Result<(), ApiError> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(sock_path)
        .map_err(|e| ApiError::internal(format!("cannot open docker.sock: {e}")))?;
    let req = format!(
        "POST /v1.43/containers/{container_id}/restart?t=10 HTTP/1.1\r\nHost: docker\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| ApiError::internal(format!("docker.sock write: {e}")))?;
    let mut buf = [0u8; 1024];
    let n = stream
        .read(&mut buf)
        .map_err(|e| ApiError::internal(format!("docker.sock read: {e}")))?;
    let resp = String::from_utf8_lossy(&buf[..n]);
    // 容器重启会掐断自身，响应可能读到一半就断——2xx 开头即算成功。
    if resp.starts_with("HTTP/1.1 2") {
        Ok(())
    } else {
        Err(ApiError::internal(format!(
            "docker restart failed: {}",
            resp.lines().next().unwrap_or("")
        )))
    }
}
