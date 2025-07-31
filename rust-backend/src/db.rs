use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, SqlitePool};

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: i64,
    pub domain: String,
    pub scanned_by: String,
    pub grade: String,
    pub scan_time: String, // <-- Change from DateTime<Utc> to String
    pub certificate_json: String,
    pub protocols_json: String,
    pub cipher_suites_json: String,
    pub vulnerabilities_json: String,
    pub key_exchange_json: String,
    pub explanation: Option<String>,
    pub tls_scan_duration: Option<String>,
    pub details_json: String,
}

//initialize the database and create necessary tables
pub async fn init_db(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scan_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            scanned_by TEXT NOT NULL,
            grade TEXT NOT NULL,
            scan_time DATETIME NOT NULL,
            certificate_json TEXT NOT NULL,
            protocols_json TEXT NOT NULL,
            cipher_suites_json TEXT NOT NULL,
            vulnerabilities_json TEXT NOT NULL,
            key_exchange_json TEXT NOT NULL,
            explanation TEXT,
            details_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS domain_grade_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            grade TEXT NOT NULL,
            scan_time DATETIME NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn insert_scan(
    pool: &SqlitePool,
    domain: &str,
    scanned_by: &str,
    grade: &str,
    certificate_json: &str,
    protocols_json: &str,
    cipher_suites_json: &str,
    vulnerabilities_json: &str,
    key_exchange_json: &str,
    explanation: Option<&str>,
    tls_scan_duration: Option<&str>,
    details_json: &str,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    sqlx::query(
        r#"
        INSERT INTO scan_records (
            domain, scanned_by, grade, scan_time,
            certificate_json, protocols_json, cipher_suites_json,
            vulnerabilities_json, key_exchange_json, explanation, tls_scan_duration, details_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(domain)
    .bind(scanned_by)
    .bind(grade)
    .bind(now.to_rfc3339())
    .bind(certificate_json)
    .bind(protocols_json)
    .bind(cipher_suites_json)
    .bind(vulnerabilities_json)
    .bind(key_exchange_json)
    .bind(explanation)
    .bind(tls_scan_duration)
    .bind(details_json)
    .execute(pool)
    .await?;

    // Also insert into grade history
    sqlx::query(
        r#"
        INSERT INTO domain_grade_history (domain, grade, scan_time)
        VALUES (?, ?, ?)
        "#,
    )
    .bind(domain)
    .bind(grade)
    .bind(now.to_rfc3339())
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn cleanup_old_scans(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        DELETE FROM scan_records
        WHERE scan_time < datetime('now', '-7 days')
        "#,
    )
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_recent_scan(
    pool: &SqlitePool,
    domain: &str,
) -> Result<Option<ScanRecord>, sqlx::Error> {
    let record = sqlx::query_as::<_, ScanRecord>(
        r#"
        SELECT * FROM scan_records
        WHERE domain = ? AND scan_time >= datetime('now', '-7 days')
        ORDER BY scan_time DESC
        LIMIT 1
        "#,
    )
    .bind(domain)
    .fetch_optional(pool)
    .await?;
    Ok(record)
}
