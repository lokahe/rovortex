//! 找回密码：发重置邮件 / 邮件内表单提交新密码。
//!
//! 防枚举与频率限制语义同 magic.rs：request 恒 202（未注册/无密码邮箱不发信），
//! 发信走进程内 MailRateLimiter（同邮箱 1 分钟 1 条）。

use axum::extract::{ConnectInfo, Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::net::SocketAddr;

use crate::error::ApiError;
use crate::routes::users::client_ip;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

/// POST /api/auth/password-reset/request —— 202 Accepted（防枚举：恒 202）。
pub async fn request_reset(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<PasswordResetRequest>,
) -> Result<StatusCode, ApiError> {
    let ip = client_ip(&headers, addr);
    if let Err(reason) = state.mail_limiter.check(&req.email) {
        return Err(ApiError::too_many_requests(reason));
    }
    state.users.request_password_reset(&req.email, &ip).await?;
    Ok(StatusCode::ACCEPTED)
}

#[derive(Debug, Deserialize)]
pub struct ConfirmParams {
    pub token: String,
}

/// GET /api/auth/password-reset/confirm?token=... —— 邮件链接落地的设置新密码页。
/// token 有效则渲染表单；无效则渲染错误页（与 verify_email.rs 的结果页同风格）。
pub async fn confirm_form(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<ConfirmParams>,
) -> Result<Response, Response> {
    let ip = client_ip(&headers, addr);
    let _ = (&state, &ip);
    // token 只做格式预检（真实校验在提交一步，避免 GET 泄露 token 是否有效）；
    // 这里始终渲染表单，提交时才消费 token。
    if params.token.is_empty() {
        return Err(error_page("链接无效", "重置链接无效或已过期，请重新发起密码重置。"));
    }
    Ok(form_page(&params.token))
}

#[derive(Debug, Deserialize)]
pub struct ResetForm {
    pub token: String,
    pub new_password: String,
}

/// POST /api/auth/password-reset/confirm —— 表单提交：消费 token 设新密码。
pub async fn confirm_submit(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<ResetForm>,
) -> Result<Response, Response> {
    let ip = client_ip(&headers, addr);
    match state
        .users
        .confirm_password_reset(&form.token, &form.new_password, &ip)
        .await
    {
        Ok(()) => Ok(result_page(
            "密码已重置",
            "你的密码已更新，之前的登录会话已全部失效。请使用新密码重新登录。",
        )),
        Err(_) => Err(error_page(
            "重置失败",
            "重置链接无效、已过期或新密码不合规，请重新发起密码重置。",
        )),
    }
}

/// 极简设置新密码表单页（无前端依赖，API 服务直接渲染）。
fn form_page(token: &str) -> Response {
    let body = format!(
        r#"<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8"><title>设置新密码</title></head>
<body style="font-family:sans-serif;max-width:420px;margin:0 auto;padding-top:60px">
<h1>设置新密码</h1>
<form method="post" action="/api/auth/password-reset/confirm">
  <input type="hidden" name="token" value="{token}">
  <p><input type="password" name="new_password" placeholder="新密码" required minlength="8"
     style="width:100%;padding:10px;box-sizing:border-box;border:1px solid #ccc;border-radius:6px"></p>
  <p><button type="submit" style="width:100%;padding:10px;background:#4f46e5;color:#fff;border:0;border-radius:6px;cursor:pointer">确认重置</button></p>
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
