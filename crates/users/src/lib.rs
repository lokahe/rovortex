//! Rovortex 用户模块 —— 核心业务层（框架无关）。
//!
//! 本 crate 刻意不依赖任何 Web 框架 / 序列化框架，只包含用户领域的业务逻辑：
//!
//! - [`domain`]：实体、值对象校验、领域错误
//! - [`password`]：密码哈希（Argon2id）
//! - [`repository`]：仓储抽象（持久化无关的契约）
//! - [`service`]：用例编排（注册 / 登录）
//! - [`in_memory`]：内存仓储实现（数据库落地前的过渡实现）
//!
//! 依赖方向：`gateway_api → users`，本 crate 永远不反向依赖表现层。

pub mod domain;
pub mod password;
pub mod repository;
pub mod service;

pub use domain::{NewUser, User, UserError};
pub use repository::UserRepository;
pub use service::UserService;
