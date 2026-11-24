//! 密码登录 / 会话刷新 / 登出 / 改密码。

use uuid::Uuid;

use super::{Session, SessionContext, UserService, token_utils::hash_refresh_token};
use crate::audit::AuditAction;
use crate::domain::UserError;
use crate::password::{hash_password, verify_password};


impl UserService {
    /// 登录：限流检查 → 查用户 → 验密码 → 签会话。
    ///
    /// `guard_key` 由表现层按 (client_ip, login) 生成后传入；
    /// 锁定中的尝试直接拒绝，不消耗 Argon2 算力。
    pub async fn login(
        &self,
        guard_key: &str,
        login: &str,
        password: &str,
        client_ip: &str,
        ctx: &SessionContext,
    ) -> Result<Session, UserError> {
        self.login_guard.check(guard_key).await?;
        let result = self.login_inner(login, password, ctx).await;
        match &result {
            Ok(s) => {
                self.audit(
                    Some(s.user.id),
                    AuditAction::LoginSuccess,
                    format!("login={login}"),
                    client_ip,
                ).await;
                self.login_guard.record_success(guard_key).await
            }
            Err(UserError::InvalidCredentials) => {
                self.audit(None, AuditAction::LoginFailure, format!("login={login}"), client_ip).await;
                self.login_guard.record_failure(guard_key).await
            }
            // 用户不存在也计入失败（防枚举语义下这同样是 InvalidCredentials，
            // 但防御性处理：其他错误不计入）
            Err(UserError::UserNotFound) => {
                self.audit(None, AuditAction::LoginFailure, format!("login={login}"), client_ip).await;
                self.login_guard.record_failure(guard_key).await
            }
            Err(_) => {}
        }
        result
    }

    async fn login_inner(&self, login: &str, password: &str, ctx: &SessionContext) -> Result<Session, UserError> {
        let user = self
            .repo
            .find_by_login(login)
            .await?
            .ok_or(UserError::InvalidCredentials)?;

        // 无密码账号（纯 OAuth/Magic 用户）：不提示「未设置密码」，恒 InvalidCredentials 防枚举。
        let Some(hash) = user.password_hash.as_deref() else {
            return Err(UserError::InvalidCredentials);
        };
        if !verify_password(password, hash) {
            return Err(UserError::InvalidCredentials);
        }
        self.issue_session(user, ctx).await
    }

    /// 用 refresh token 换取新会话（轮换：旧 token 立即吊销）。
    pub async fn refresh(&self, raw_token: &str, client_ip: &str, ctx: &SessionContext) -> Result<Session, UserError> {
        let token_hash = hash_refresh_token(raw_token);
        let result = self.refresh_inner(&token_hash, client_ip, ctx).await;
        if result.is_err() {
            self.audit(None, AuditAction::RefreshFailure, "invalid refresh token", client_ip).await;
        }
        result
    }

    async fn refresh_inner(&self, token_hash: &str, client_ip: &str, ctx: &SessionContext) -> Result<Session, UserError> {
        let (user_id, _) = self
            .refresh
            .find_active_by_hash(token_hash)
            .await?
            .ok_or(UserError::InvalidRefreshToken)?;
        self.refresh.revoke_by_hash(token_hash).await?;

        let user = self
            .repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::UserNotFound)?;
        self.audit(Some(user.id), AuditAction::RefreshSuccess, "", client_ip).await;
        self.issue_session(user, ctx).await
    }

    /// 登出：吊销给定 refresh token（幂等：token 无效也返回成功）。
    pub async fn logout(&self, raw_token: &str, client_ip: &str) -> Result<(), UserError> {
        let hash = hash_refresh_token(raw_token);
        // 吊销前反查归属，便于审计关联用户（查不到也照常吊销，幂等语义不变）。
        let owner = self
            .refresh
            .find_active_by_hash(&hash)
            .await?
            .map(|(uid, _)| uid);
        self.audit(owner, AuditAction::Logout, "", client_ip).await;
        self.refresh.revoke_by_hash(&hash).await
    }

    /// 修改密码：验证旧密码 → 重哈希 → 吊销该用户全部会话。
    ///
    /// 无密码账号（OAuth/Magic 用户首次设密码）请用 [`UserService::set_password`]。
    pub async fn change_password(
        &self,
        user_id: Uuid,
        old_password: &str,
        new_password: &str,
        client_ip: &str,
    ) -> Result<(), UserError> {
        self.validate_password_len(new_password)?;
        let user = self
            .repo
            .find_by_id(user_id)
            .await?
            .ok_or(UserError::UserNotFound)?;
        let Some(old_hash) = user.password_hash.as_deref() else {
            return Err(UserError::InvalidCredentials);
        };
        if !verify_password(old_password, old_hash) {
            self.audit(Some(user_id), AuditAction::LoginFailure, "change_password: old password mismatch", client_ip).await;
            return Err(UserError::InvalidCredentials);
        }
        let new_hash = hash_password(new_password)?;
        self.repo
            .update_password_hash(user_id, &new_hash)
            .await?;
        self.refresh.revoke_all_for_user(user_id).await?;
        self.audit(Some(user_id), AuditAction::PasswordChanged, "", client_ip).await;
        Ok(())
    }
}
