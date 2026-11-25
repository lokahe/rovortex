//! 进程内定时任务框架（「cron」那半；多实例时再补 PG advisory lock 那半）。
//!
//! 设计：
//! - 声明式注册：每个任务一个 `JobDef`（name/doc/default interval/run 闭包），
//!   集中在 `build_handles()` 一处；新增任务 = 加函数 + 加一条注册，不碰框架。
//! - 运行期可调：interval 与开关从 AppSettings 读（键 `job.<name>.enabled` /
//!   `job.<name>.interval_secs`），管理页改完下一轮 tick 生效，无需重启。
//! - 状态可观测：last_run（时间/耗时/结果摘要）留在 handle 内，管理端点直接读。
//!
//! 安全边界：任务的 SQL 模板编译期写死（storage_pg 实现），管理页只能操作
//! 已注册任务，不能注入任意 SQL——管理页是遥控器，不是 IDE。
//!
//! 依赖注入：run 闭包只拿所需的三个服务（users 业务/settings/audit），
//! 不依赖 AppState（组合根在 AppState 完成前就要 spawn）。

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rovortex_users::{AppSettings, AuditRepository, UserService};
use tokio::sync::Mutex;

/// 任务运行所需的依赖切片。
#[derive(Clone)]
pub struct JobCtx {
    pub users: Arc<UserService>,
    pub settings: Arc<AppSettings>,
    pub audit: Arc<dyn AuditRepository>,
}

type JobFuture = Pin<Box<dyn Future<Output = Result<String, String>> + Send>>;

/// 任务定义（声明式，编译期注册）。
pub struct JobDef {
    pub name: &'static str,
    pub doc: &'static str,
    /// 默认频率（秒）；运行期可被 `job.<name>.interval_secs` 覆盖。
    pub default_interval_secs: u64,
    pub default_enabled: bool,
    /// 默认开启时的业务参数（保留天数等），键约定 `job.<name>.*`。
    pub run: fn(JobCtx) -> JobFuture,
}

/// 一次执行的结果。
#[derive(Debug, Clone, serde::Serialize)]
pub struct LastRun {
    pub at: chrono::DateTime<chrono::Utc>,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
}

pub struct JobHandle {
    pub def: &'static JobDef,
    enabled: AtomicBool,
    last_run: Mutex<Option<LastRun>>,
    /// 运行期 interval（秒）；启动时从 settings 加载，管理端点可改。
    interval_secs: Mutex<u64>,
}

impl JobHandle {
    pub fn name(&self) -> &'static str {
        self.def.name
    }

    pub fn doc(&self) -> &'static str {
        self.def.doc
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    pub async fn last_run(&self) -> Option<LastRun> {
        self.last_run.lock().await.clone()
    }

    pub async fn interval_secs(&self) -> u64 {
        *self.interval_secs.lock().await
    }

    pub async fn set_interval_secs(&self, secs: u64) {
        *self.interval_secs.lock().await = secs.max(60);
    }

    /// 立即执行一次（手动触发也走这里，写 last_run）。
    pub async fn run_once(&self, ctx: JobCtx) -> LastRun {
        let started = std::time::Instant::now();
        let result = (self.def.run)(ctx).await;
        let run = match result {
            Ok(ok) => LastRun {
                at: chrono::Utc::now(),
                elapsed_ms: started.elapsed().as_millis() as u64,
                ok: Some(ok),
                err: None,
            },
            Err(err) => LastRun {
                at: chrono::Utc::now(),
                elapsed_ms: started.elapsed().as_millis() as u64,
                ok: None,
                err: Some(err),
            },
        };
        *self.last_run.lock().await = Some(run.clone());
        run
    }
}

fn enabled_key(name: &str) -> String {
    format!("job.{name}.enabled")
}
fn interval_key(name: &str) -> String {
    format!("job.{name}.interval_secs")
}

/// 全部任务注册处。新增任务：写 run 函数 + 在此追加 JobDef。
fn defs() -> Vec<JobDef> {
    vec![
        JobDef {
            name: "refresh_token_cleanup",
            doc: "删除过期 7 天以上的 refresh token（会话记录，含设备描述）",
            default_interval_secs: 3600,
            default_enabled: true,
            run: |ctx| Box::pin(async move {
                let days = ctx.settings.get_u64("job.refresh_token_cleanup.retention_days", 7).await;
                let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
                let n = ctx.users.purge_expired_refresh_tokens(cutoff).await.map_err(|e| e.to_string())?;
                Ok(format!("purged {n} expired refresh tokens (older than {days}d)"))
            }),
        },
        JobDef {
            name: "email_verification_cleanup",
            doc: "删除已消费/过期 1 天以上的邮箱验证记录",
            default_interval_secs: 3600,
            default_enabled: true,
            run: |ctx| Box::pin(async move {
                let days = ctx.settings.get_u64("job.email_verification_cleanup.retention_days", 1).await;
                let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
                let n = ctx.users.purge_stale_email_verifications(cutoff).await.map_err(|e| e.to_string())?;
                Ok(format!("purged {n} stale email verifications (older than {days}d)"))
            }),
        },
        JobDef {
            name: "account_purge",
            doc: "硬删冷静期（默认 30 天）满的注销账号；会话与外部身份级联删除，审计留痕",
            default_interval_secs: 3600,
            default_enabled: true,
            run: |ctx| Box::pin(async move {
                let days = ctx.settings.get_u64("job.account_purge.grace_days", 30).await;
                let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
                let n = ctx.users.purge_deleted_accounts(cutoff).await.map_err(|e| e.to_string())?;
                if n > 0 {
                    let _ = ctx.audit.append(rovortex_users::NewAuditLog {
                        user_id: None,
                        action: rovortex_users::AuditAction::AccountsPurged,
                        detail: format!("count={n} grace_days={days}"),
                        client_ip: String::new(),
                    }).await;
                }
                Ok(format!("purged {n} deleted accounts (grace {days}d)"))
            }),
        },
    ]
}

/// 组合根调用：注册句柄（从 settings 加载开关/interval）+ spawn 循环。
/// 单实例假设；多实例时在 run_once 外包 pg_try_advisory_lock（见 reference-kerkour）。
pub fn spawn_all(ctx: JobCtx) -> Vec<Arc<JobHandle>> {
    let mut handles = Vec::new();
    for def in defs() {
        // Box::leak：定义与进程同寿命，换来 &'static 引用省一层 Arc。
        let def: &'static JobDef = Box::leak(Box::new(def));
        let handle = Arc::new(JobHandle {
            def,
            enabled: AtomicBool::new(def.default_enabled),
            last_run: Mutex::new(None),
            interval_secs: Mutex::new(def.default_interval_secs),
        });
        let task_ctx = ctx.clone();
        let h = handle.clone();
        tokio::spawn(async move {
            // 加载持久化状态（app_settings），缺省用定义默认值。
            let persisted = task_ctx
                .settings
                .get_bool(&enabled_key(def.name), def.default_enabled)
                .await;
            h.set_enabled(persisted);
            let secs = task_ctx
                .settings
                .get_u64(&interval_key(def.name), def.default_interval_secs)
                .await;
            h.set_interval_secs(secs).await;

            loop {
                let interval = h.interval_secs().await;
                tokio::time::sleep(Duration::from_secs(interval)).await;
                if !h.is_enabled() {
                    continue;
                }
                let run = h.run_once(task_ctx.clone()).await;
                if let Some(err) = &run.err {
                    tracing::warn!(job = def.name, error = %err, "job failed");
                } else {
                    tracing::info!(job = def.name, result = run.ok.as_deref().unwrap_or(""), "job ok");
                }
            }
        });
        handles.push(handle);
    }
    handles
}
