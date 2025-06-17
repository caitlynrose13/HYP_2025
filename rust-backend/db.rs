use sqlx::{SqlitePool, sqlite::SqlitePoolOptions}; //used to handle multiple requests to db. PoolOptions allows config of pool
use std::env;

//Returns either a SqlitePool or Error Message. Establish connection to the database
pub async fn establish_connection() -> Result<SqlitePool, sqlx::Error> {
    dotenvy::dotenv(); // Load environment variables from .env 

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in .env file"); //not found means send err message

    //max 5 connections
    SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
}
