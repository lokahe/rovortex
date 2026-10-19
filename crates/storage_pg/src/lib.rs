//! PostgreSQL 持久化实现：`rovortex-users` 的 `UserRepository` 落地版本。

pub mod repository;

pub use repository::PgUserRepository;
