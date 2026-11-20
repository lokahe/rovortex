//! GitHub / Google OAuth 登录：authorize 跳转 + callback 换会话。
//!
//! 协议细节只住本模块；业务层只见 `(provider, provider_uid, email)` 三元组。

use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use std::net::SocketAddr;
use rovortex_users::ExternalProfile;
use serde::Deserialize;

use crate::state::AppState;

/// GitHub OAuth App 凭据（组合根从环境变量注入）。
#[derive(Clone)]
pub struct GithubOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
}

const AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
const TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
const USER_URL: &str = "https://api.github.com/user";
const EMAILS_URL: &str = "https://api.github.com/user/emails";
const STATE_COOKIE: &str = "rovortex_oauth_state";
/// state cookie 的存活时间：覆盖「跳转授权 → 用户操作 → 回调」全程。
const STATE_COOKIE_MAX_AGE_SECS: i64 = 600;

/// GET /api/auth/oauth/github —— 302 跳 GitHub 授权页。
///
/// 生成随机 state 存入短命 HttpOnly cookie，回调时比对防 CSRF。
pub async fn github_authorize(
    State(state): State<AppState>,
) -> Result<Response, ApiError> {
    let config = state
        .oauth_github
        .as_ref()
        .ok_or(ApiError::not_found())?;
    let oauth_state = new_oauth_state();

    // scope=user:email 让 GitHub 报告邮箱（可能含私有邮箱）
    let redirect = format!(
        "{AUTHORIZE_URL}?client_id={}&redirect_uri={}&state={}&scope=user%3Aemail&allow_signup=true",
        urlencode(&config.client_id),
        urlencode(&callback_url()),
        urlencode(&oauth_state),
    );

    let mut response = Redirect::to(&redirect).into_response();
    let cookie = format!(
        "{STATE_COOKIE}={oauth_state}; Path=/; HttpOnly; SameSite=Lax; Max-Age={STATE_COOKIE_MAX_AGE_SECS}"
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        header::HeaderValue::from_str(&cookie)
            .map_err(|_| ApiError::internal("bad cookie".into()))?,
    );
    Ok(response)
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
    /// 用户拒绝授权时 GitHub 回传 error（无 code）。
    pub error: Option<String>,
}

/// GET /api/auth/oauth/github/callback?code=...&state=...
pub async fn github_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::Query(query): axum::extract::Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let config = state
        .oauth_github
        .as_ref()
        .ok_or(ApiError::not_found())?;

    // 用户拒绝授权：GitHub 常规做法是 302 回前端错误页；这里统一 422 简化
    if query.error.is_some() {
        return Err(ApiError::bad_request("oauth denied".into()));
    }

    // CSRF：cookie 里的 state 必须与回调一致
    let cookie_state = read_cookie(&headers, STATE_COOKIE)
        .ok_or(ApiError::bad_request("missing oauth state".into()))?;
    if !constant_time_eq(cookie_state.as_bytes(), query.state.as_bytes()) {
        return Err(ApiError::bad_request("oauth state mismatch".into()));
    }

    // code → access token
    let access_token = exchange_code(config, &query.code).await?;

    // access token → 用户信息
    let github_user = fetch_github_user(&access_token).await?;
    // GitHub 的 email 可能为 null（用户设了私有邮箱）：走 /user/emails 拿 verified 主邮箱
    let email = match github_user.email {
        Some(e) => Some(e),
        None => fetch_primary_email(&access_token).await?,
    }
    .map(|e| e.to_string());

    // 平台资料 → 规范字段映射 + raw JSON 缓存（裁剪掉无关长字段）
    let raw = serde_json::json!({
        "login": github_user.login,
        "name": github_user.name,
        "avatar_url": github_user.avatar_url,
        "bio": github_user.bio,
        "blog": github_user.blog,
    });
    let profile = ExternalProfile {
        display_name: Some(
            github_user
                .name
                .unwrap_or_else(|| github_user.login.clone()),
        ),
        avatar_url: Some(github_user.avatar_url),
        bio: github_user.bio,
        website_url: normalize_url(github_user.blog),
        raw: Some(raw),
    };

    let session = state
        .users
        .login_with_identity(
            "github",
            &github_user.id.to_string(),
            email.as_deref(),
            Some(&profile),
            "oauth",
            &crate::routes::users::session_context(&headers, addr),
        )
        .await?;

    let auth = auth_response(
        &state.tokens,
        session.user,
        session.refresh_token,
        session.refresh_expires_at,
    )?;
    Ok((StatusCode::OK, Json(auth)).into_response())
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GithubUser {
    id: i64,
    /// GitHub 私有邮箱需要 user:email scope；未设置公共邮箱时可能为 None。
    email: Option<String>,
    /// GitHub 登录名（@handle），用于 display_name fallback 与用户名生成。
    login: String,
    /// 用户设置的显示名。
    name: Option<String>,
    /// 头像 URL（GitHub 恒有）。
    avatar_url: String,
    /// 简介。
    bio: Option<String>,
    /// 个人主页（可能无协议，如 "example.com"）。
    blog: Option<String>,
}

/// 补全无协议的 URL；空串/非法值丢弃。只做归一，不做可达性校验。
fn normalize_url(url: Option<String>) -> Option<String> {
    let u = url?.trim().to_string();
    if u.is_empty() {
        return None;
    }
    if u.starts_with("http://") || u.starts_with("https://") {
        Some(u)
    } else {
        Some(format!("https://{u}"))
    }
}

async fn exchange_code(config: &GithubOAuthConfig, code: &str) -> Result<String, ApiError> {
    let client = reqwest_client();
    let redirect_uri = callback_url();
    let params = [
        ("client_id", config.client_id.as_str()),
        ("client_secret", config.client_secret.as_str()),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
    ];
    let resp = client
        .post(TOKEN_URL)
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("github token request failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(ApiError::bad_request("oauth code invalid".into()));
    }
    let token: TokenResponse = resp
        .json()
        .await
        .map_err(|e| ApiError::internal(format!("github token parse failed: {e}")))?;
    Ok(token.access_token)
}

async fn fetch_github_user(access_token: &str) -> Result<GithubUser, ApiError> {
    let client = reqwest_client();
    let resp = client
        .get(USER_URL)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "rovortex-api")
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("github user request failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(ApiError::bad_request("oauth token invalid".into()));
    }
    resp.json()
        .await
        .map_err(|e| ApiError::internal(format!("github user parse failed: {e}")))
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

/// GET /user/emails：返回用户全部邮箱，取 primary 且 verified 的那条。
/// 设计约束：所有 provider 必须报告 verified email 才允许绑定（AUTH_V2.md §3）。
async fn fetch_primary_email(access_token: &str) -> Result<Option<String>, ApiError> {
    let client = reqwest_client();
    let resp = client
        .get(EMAILS_URL)
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "rovortex-api")
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("github emails request failed: {e}")))?;
    if !resp.status().is_success() {
        tracing::warn!(status = %resp.status(), "github /user/emails failed");
        return Ok(None);
    }
    let emails: Vec<GithubEmail> = resp
        .json()
        .await
        .map_err(|e| ApiError::internal(format!("github emails parse failed: {e}")))?;
    Ok(emails
        .into_iter()
        .find(|e| e.primary && e.verified)
        .map(|e| e.email))
}

fn callback_url() -> String {
    let base = std::env::var("ROVORTEX_VERIFY_URL_BASE")
        .unwrap_or_else(|_| "http://localhost:8080".into());
    format!("{base}/api/auth/oauth/github/callback")
}

/// 128 位随机 state，URL 安全 Base64。
fn new_oauth_state() -> String {
    use base64::Engine as _;
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|pair| {
        let pair = pair.trim();
        let (k, v) = pair.split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn reqwest_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("reqwest client")
}

// ---- Google OAuth（OIDC）----

/// Google OAuth Client 凭据（组合根从环境变量注入）。
#[derive(Clone)]
pub struct GoogleOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
}

const GOOGLE_AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const GOOGLE_STATE_COOKIE: &str = "rovortex_oauth_state_google";

/// GET /api/auth/oauth/google —— 302 跳 Google 授权页。
pub async fn google_authorize(
    State(state): State<AppState>,
) -> Result<Response, ApiError> {
    let config = state
        .oauth_google
        .as_ref()
        .ok_or(ApiError::not_found())?;
    let oauth_state = new_oauth_state();

    // scope=openid email profile；access_type=online（不取 refresh token，只登录用）
    let redirect = format!(
        "{GOOGLE_AUTHORIZE_URL}?client_id={}&redirect_uri={}&response_type=code&state={}&scope=openid%20email%20profile&access_type=online",
        urlencode(&config.client_id),
        urlencode(&google_callback_url()),
        urlencode(&oauth_state),
    );

    let mut response = Redirect::to(&redirect).into_response();
    let cookie = format!(
        "{GOOGLE_STATE_COOKIE}={oauth_state}; Path=/; HttpOnly; SameSite=Lax; Max-Age={STATE_COOKIE_MAX_AGE_SECS}"
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        header::HeaderValue::from_str(&cookie)
            .map_err(|_| ApiError::internal("bad cookie".into()))?,
    );
    Ok(response)
}

/// GET /api/auth/oauth/google/callback?code=...&state=...
pub async fn google_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::Query(query): axum::extract::Query<GoogleCallbackQuery>,
) -> Result<Response, ApiError> {
    let config = state
        .oauth_google
        .as_ref()
        .ok_or(ApiError::not_found())?;

    if query.error.is_some() {
        return Err(ApiError::bad_request("oauth denied".into()));
    }

    let cookie_state = read_cookie(&headers, GOOGLE_STATE_COOKIE)
        .ok_or(ApiError::bad_request("missing oauth state".into()))?;
    if !constant_time_eq(cookie_state.as_bytes(), query.state.as_bytes()) {
        return Err(ApiError::bad_request("oauth state mismatch".into()));
    }

    let access_token = exchange_google_code(config, &query.code).await?;
    let google_user = fetch_google_user(&access_token).await?;

    // 设计约束：所有 provider 必须报告 verified email 才允许绑定（AUTH_V2.md §3）。
    if !google_user.email_verified {
        return Err(ApiError::bad_request("google email not verified".into()));
    }

    let raw = serde_json::json!({
        "sub": google_user.sub,
        "name": google_user.name,
        "picture": google_user.picture,
        "email": google_user.email,
    });
    let profile = ExternalProfile {
        display_name: Some(
            google_user
                .name
                .clone()
                .unwrap_or_else(|| google_user.email.clone()),
        ),
        avatar_url: google_user.picture.clone(),
        bio: None,
        website_url: None,
        raw: Some(raw),
    };

    let session = state
        .users
        .login_with_identity(
            "google",
            &google_user.sub,
            Some(&google_user.email),
            Some(&profile),
            "oauth",
            &crate::routes::users::session_context(&headers, addr),
        )
        .await?;

    let auth = auth_response(
        &state.tokens,
        session.user,
        session.refresh_token,
        session.refresh_expires_at,
    )?;
    Ok((StatusCode::OK, Json(auth)).into_response())
}

#[derive(Deserialize)]
pub struct GoogleCallbackQuery {
    pub code: String,
    pub state: String,
    pub error: Option<String>,
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GoogleUser {
    /// Google 账号稳定 ID（OIDC sub），永不变化。
    sub: String,
    email: String,
    /// Google 报告的邮箱验证状态；未验证一律拒绝绑定。
    email_verified: bool,
    name: Option<String>,
    picture: Option<String>,
}

fn google_callback_url() -> String {
    let base = std::env::var("ROVORTEX_VERIFY_URL_BASE")
        .unwrap_or_else(|_| "http://localhost:8080".into());
    format!("{base}/api/auth/oauth/google/callback")
}

async fn exchange_google_code(config: &GoogleOAuthConfig, code: &str) -> Result<String, ApiError> {
    let client = reqwest_client();
    let redirect_uri = google_callback_url();
    let params = [
        ("client_id", config.client_id.as_str()),
        ("client_secret", config.client_secret.as_str()),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
        ("grant_type", "authorization_code"),
    ];
    let resp = client
        .post(GOOGLE_TOKEN_URL)
        .form(&params)
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("google token request failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(ApiError::bad_request("oauth code invalid".into()));
    }
    let token: GoogleTokenResponse = resp
        .json()
        .await
        .map_err(|e| ApiError::internal(format!("google token parse failed: {e}")))?;
    Ok(token.access_token)
}

async fn fetch_google_user(access_token: &str) -> Result<GoogleUser, ApiError> {
    let client = reqwest_client();
    let resp = client
        .get(GOOGLE_USERINFO_URL)
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .map_err(|e| ApiError::internal(format!("google userinfo request failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(ApiError::bad_request("oauth token invalid".into()));
    }
    resp.json()
        .await
        .map_err(|e| ApiError::internal(format!("google user parse failed: {e}")))
}

use crate::error::ApiError;
use crate::routes::session::auth_response;
