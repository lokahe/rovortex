//! 用户 HTTP 接口：请求 / 响应 DTO 与 handler。

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use std::net::SocketAddr;
use chrono::{DateTime, Utc};
use rovortex_users::User;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// 可选：想要展示的用户名。缺省由邮箱前缀自动生成（冲突加数字后缀）；
    /// 占用冲突返回 409，客户端可不填避免撞名。
    #[serde(default)]
    pub username: Option<String>,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// 用户名或邮箱。
    pub login: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            email: u.email,
            created_at: u.created_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    /// JWT access token（HS256，2 小时有效期）。
    pub token: String,
    /// 明文 refresh token：客户端妥善保存，用于换取新 access token。
    pub refresh_token: String,
    pub refresh_expires_at: DateTime<Utc>,
}

/// POST /api/users/register —— 201 Created
pub async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), ApiError> {
    let ip = client_ip(&headers, addr);
    let session = state
        .users
        .register(req.username.as_deref(), &req.email, &req.password, &ip, &session_context(&headers, addr))
        .await?;
    let token = state.tokens.sign(session.user.id)?;
    Ok((
        StatusCode::CREATED,
        Json(AuthResponse {
            user: session.user.into(),
            token,
            refresh_token: session.refresh_token,
            refresh_expires_at: session.refresh_expires_at,
        }),
    ))
}

/// POST /api/users/login —— 200 OK
///
/// 限流键 (client_ip, login)：连续失败达到阈值（默认 9）锁 15 分钟，均可配。
/// 客户端 IP 取 X-Forwarded-For 首段（Caddy 反代注入），回退 ConnectInfo。
pub async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let ip = client_ip(&headers, addr);
    let key = rovortex_users::guard_key(&ip, &req.login);
    let ctx = session_context(&headers, addr);
    let session = state
        .users
        .login(&key, &req.login, &req.password, &ip, &ctx)
        .await?;
    let token = state.tokens.sign(session.user.id)?;
    Ok(Json(AuthResponse {
        user: session.user.into(),
        token,
        refresh_token: session.refresh_token,
        refresh_expires_at: session.refresh_expires_at,
    }))
}

/// Caddy 反代会覆盖 X-Forwarded-For 为真实客户端地址；直连时回退 socket 地址。
pub fn client_ip(headers: &axum::http::HeaderMap, addr: SocketAddr) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| addr.ip().to_string())
}

/// 粗粒度 IP：只留前两段（IPv4 /16，IPv6 /32），完整 IP 不落会话表。
fn coarse_ip(ip: &str) -> String {
    let parts: Vec<&str> = ip.split(':').next().unwrap_or(ip).split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.*", parts[0], parts[1])
    } else {
        // IPv6：取前两个冒号段
        let segs: Vec<&str> = ip.split(':').collect();
        if segs.len() >= 2 {
            format!("{}:{}::*", segs[0], segs[1])
        } else {
            "unknown".into()
        }
    }
}

/// 从 UA 解析出人类可读的设备描述（如 "Chrome 130 · Windows 10"）。
/// 只求"人认设备"，不追求完备——未知一律回落原 UA 前 64 字符。
fn describe_ua(ua: &str) -> String {
    let lower = ua.to_ascii_lowercase();
    let browser = if lower.contains("edg/") {
        "Edge".into()
    } else if lower.contains("opr/") || lower.contains("opera") {
        "Opera".into()
    } else if lower.contains("chrome/") && !lower.contains("chromium") {
        version_of(&lower, "chrome/").map(|v| format!("Chrome {v}")).unwrap_or_else(|| "Chrome".into())
    } else if lower.contains("firefox/") {
        version_of(&lower, "firefox/").map(|v| format!("Firefox {v}")).unwrap_or_else(|| "Firefox".into())
    } else if lower.contains("okhttp") {
        version_of(&lower, "okhttp/").map(|v| format!("okhttp {v}")).unwrap_or_else(|| "Android app".into())
    } else if lower.contains("safari") && lower.contains("mobile") {
        "Mobile Safari".into()
    } else if lower.contains("safari") {
        "Safari".into()
    } else {
        // 未知客户端：截断原 UA，避免长串落库
        return ua.chars().take(64).collect();
    };

    let os = if lower.contains("windows") {
        "Windows"
    } else if lower.contains("android") {
        "Android"
    } else if lower.contains("iphone") || lower.contains("ipad") {
        "iOS"
    } else if lower.contains("mac os") || lower.contains("macintosh") {
        "macOS"
    } else if lower.contains("linux") {
        "Linux"
    } else {
        "Unknown OS"
    };
    format!("{browser} · {os}")
}

fn version_of(ua: &str, marker: &str) -> Option<String> {
    let idx = ua.find(marker)? + marker.len();
    let rest = &ua[idx..];
    let major: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if major.is_empty() {
        None
    } else {
        Some(major)
    }
}

/// 提取会话签发上下文：device_label 优先取客户端自报（X-Device-Name，≤64 字符），
/// 否则用 UA 解析结果；ip 只存粗粒度段。
pub fn session_context(headers: &axum::http::HeaderMap, addr: SocketAddr) -> rovortex_users::SessionContext {
    let ua_raw = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let device_label = headers
        .get("x-device-name")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(64).collect::<String>());
    let ip = client_ip(headers, addr);
    rovortex_users::SessionContext {
        device_label,
        ua: (!ua_raw.is_empty()).then(|| describe_ua(ua_raw)),
        ip: Some(coarse_ip(&ip)),
    }
}
