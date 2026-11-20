//! 邮箱注册（不建号式）：发双通道验证邮件 / 验证码确认 / 链接表单确认。
//!
//! request 恒 202（防枚举：已注册邮箱不发信）。发信走 MailRateLimiter。
//! confirm-code 端点自带限流（每邮箱+IP 5 次 / 15 分钟，进程内），
//! 6 位码空间 10^6，限流后爆破不可行。

use axum::extract::{ConnectInfo, Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::ApiError;
use crate::routes::users::{client_ip, AuthResponse};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub email: String,
}

/// POST /api/auth/signup/request —— 202 Accepted（防枚举：恒 202）。
pub async fn request_signup(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<SignupRequest>,
) -> Result<StatusCode, ApiError> {
    let ip = client_ip(&headers, addr);
    if let Err(reason) = state.mail_limiter.check(&req.email) {
        return Err(ApiError::too_many_requests(reason));
    }
    state.users.request_signup(&req.email, &ip).await?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(Debug, Deserialize)]
pub struct ConfirmCodeRequest {
    pub email: String,
    /// 6 位数字验证码。
    pub code: String,
    pub password: String,
    /// 可选：想要展示的用户名。缺省由邮箱前缀自动生成。
    #[serde(default)]
    pub username: Option<String>,
}

/// confirm-code 尝试限流参数。
const CODE_ATTEMPTS_LIMIT: usize = 5;
const CODE_ATTEMPTS_WINDOW: Duration = Duration::from_secs(15 * 60);

/// 进程内确认尝试限流：key = (ip, email)。
pub struct ConfirmCodeLimiter {
    attempts: Mutex<HashMap<String, VecDeque<Instant>>>,
}

use std::collections::VecDeque;

impl ConfirmCodeLimiter {
    pub fn new() -> Self {
        Self { attempts: Mutex::new(HashMap::new()) }
    }

    pub fn check(&self, key: &str) -> Result<(), &'static str> {
        let now = Instant::now();
        let mut attempts = self.attempts.lock().unwrap();
        let hist = attempts.entry(key.to_string()).or_default();
        while hist.front().is_some_and(|t| now.duration_since(*t) > CODE_ATTEMPTS_WINDOW) {
            hist.pop_front();
        }
        if hist.len() >= CODE_ATTEMPTS_LIMIT {
            return Err("too many attempts, try again later");
        }
        hist.push_back(now);
        attempts.retain(|_, h| h.back().is_some_and(|t| now.duration_since(*t) <= CODE_ATTEMPTS_WINDOW));
        Ok(())
    }
}

/// POST /api/auth/signup/confirm-code —— 201 Created（验证码通道，App 用）。
pub async fn confirm_code(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ConfirmCodeRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), ApiError> {
    let ip = client_ip(&headers, addr);
    let key = format!("{}|{}", ip, req.email.to_lowercase());
    if let Err(reason) = state.confirm_code_limiter.check(&key) {
        return Err(ApiError::too_many_requests(reason));
    }
    let session = state
        .users
        .confirm_signup_code(
            &req.email,
            &req.code,
            &req.password,
            req.username.as_deref(),
            &ip,
            &crate::routes::users::session_context(&headers, addr),
        )
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

#[derive(Debug, Deserialize)]
pub struct ConfirmParams {
    pub token: String,
}

/// GET /api/auth/signup/confirm?token=... —— 邮件链接落地的完成注册页（PC）。
/// token 只做格式预检，真实校验在提交一步。
pub async fn confirm_form(
    axum::extract::Query(params): axum::extract::Query<ConfirmParams>,
) -> Result<Response, Response> {
    if params.token.is_empty() {
        return Err(error_page("链接无效", "注册链接无效或已过期，请回到应用重新发起注册。"));
    }
    Ok(form_page(&params.token))
}

#[derive(Debug, Deserialize)]
pub struct SignupForm {
    pub token: String,
    pub password: String,
}

/// POST /api/auth/signup/confirm —— 表单提交：消费链接 token 建号。
pub async fn confirm_submit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<SignupForm>,
) -> Result<Response, Response> {
    let ip = client_ip(&headers, addr);
    match state
        .users
        .confirm_signup_link(&form.token, &form.password, &ip, &crate::routes::users::session_context(&headers, addr))
        .await
    {
        Ok(_) => Ok(result_page(
            "注册成功",
            "账号已创建并完成邮箱验证。请回到应用登录。",
        )),
        Err(_) => Err(error_page(
            "注册失败",
            "注册链接无效、已过期或密码不合规，请回到应用重新发起注册。",
        )),
    }
}

/// 极简完成注册表单页（无前端依赖，API 服务直接渲染）。
fn form_page(token: &str) -> Response {
    let body = format!(
        r#"<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8"><title>完成注册</title></head>
<body style="font-family:sans-serif;max-width:420px;margin:0 auto;padding-top:60px">
<h1>完成注册</h1>
<p style="color:#666">设置你的账号密码以完成注册：</p>
<form method="post" action="/api/auth/signup/confirm">
  <input type="hidden" name="token" value="{token}">
  <p><input type="password" name="password" placeholder="密码（至少 8 位）" required minlength="8"
     style="width:100%;padding:10px;box-sizing:border-box;border:1px solid #ccc;border-radius:6px"></p>
  <p><button type="submit" style="width:100%;padding:10px;background:#4f46e5;color:#fff;border:0;border-radius:6px;cursor:pointer">创建账号</button></p>
</form>
</body></html>"#
    );
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

pub fn result_page(title: &str, detail: &str) -> Response {
    let body = format!(
        r#"<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8"><title>{title}</title></head>
<body style="font-family:sans-serif;text-align:center;padding-top:80px">
<h1>{title}</h1><p style="color:#666">{detail}</p>
</body></html>"#
    );
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

pub fn error_page(title: &str, detail: &str) -> Response {
    result_page(title, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_code_limiter_blocks_after_limit() {
        let limiter = ConfirmCodeLimiter::new();
        let key = "1.2.3.4|a@b.com";
        for _ in 0..CODE_ATTEMPTS_LIMIT {
            assert!(limiter.check(key).is_ok());
        }
        assert!(limiter.check(key).is_err(), "6th attempt blocked");
        // 不同 key 不受影响
        assert!(limiter.check("5.6.7.8|a@b.com").is_ok());
    }
}
