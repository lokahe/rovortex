//! 邮件基础设施：Resend HTTP API 实现。
//!
//! 放在独立基础设施 crate：业务层（users）只见 MailSender trait，
//! 换邮件服务商只改这里。

use async_trait::async_trait;
use serde::Serialize;

use rovortex_users::{MailError, MailSender};

const API_ENDPOINT: &str = "https://api.resend.com/emails";

pub struct ResendSender {
    http: reqwest::Client,
    api_key: String,
    from: String,
}

#[derive(Serialize)]
struct SendEmailRequest<'a> {
    from: &'a str,
    to: &'a str,
    subject: &'a str,
    html: &'a str,
}

impl ResendSender {
    pub fn new(api_key: &str, from: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key: api_key.to_string(),
            from: from.to_string(),
        }
    }
}

#[async_trait]
impl MailSender for ResendSender {
    async fn send(&self, to: &str, subject: &str, html: &str) -> Result<(), MailError> {
        let body = SendEmailRequest {
            from: &self.from,
            to,
            subject,
            html,
        };
        let resp = self
            .http
            .post(API_ENDPOINT)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| MailError::Service(e.to_string()))?;

        if resp.status().is_success() {
            Ok(())
        } else {
            let status = resp.status();
            let detail = resp.text().await.unwrap_or_default();
            Err(MailError::Service(format!("resend {status}: {detail}")))
        }
    }
}
