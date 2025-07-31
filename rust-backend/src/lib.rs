use sqlx::SqlitePool;
pub mod db;
pub mod handlers;
pub mod services;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
}
