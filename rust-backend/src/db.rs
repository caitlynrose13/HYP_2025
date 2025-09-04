use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row, SqlitePool};

// ===============================================
// DATABASE MODELS

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: i64,
    pub domain: String,
    pub grade: String,
    pub ssl_labs_grade: Option<String>,
    pub mozilla_observatory_grade: Option<String>,
    pub ssl_labs_scan_time: Option<f64>,
    pub mozilla_scan_time: Option<f64>,
    pub tls_scan_time: Option<f64>,
    pub total_scan_time: Option<f64>, // NEW: User experience time
    pub ssl_labs_error: Option<String>,
    pub mozilla_error: Option<String>,
    pub tls_error: Option<String>,
    pub scan_time: String,
}

#[derive(Debug, FromRow, Serialize)]
pub struct SecurityTimelineEntry {
    pub scan_time: String,
    pub grade: String,
    pub ssl_labs_grade: Option<String>,
    pub mozilla_observatory_grade: Option<String>,
    pub certificate_summary: Option<String>,
    pub protocols_summary: Option<String>,
    pub key_vulnerabilities: Option<String>,
}

// ======================================================
// DATABASE INITIALIZATION

pub async fn init_db(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Create the main scan_records table with total_scan_time
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scan_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            grade TEXT NOT NULL,
            ssl_labs_grade TEXT,
            mozilla_observatory_grade TEXT,
            ssl_labs_scan_time REAL,
            mozilla_scan_time REAL,
            tls_scan_time REAL,
            total_scan_time REAL,
            ssl_labs_error TEXT,
            mozilla_error TEXT,
            tls_error TEXT,
            scan_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create grade history table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS domain_grade_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            grade TEXT NOT NULL,
            ssl_labs_grade TEXT,
            mozilla_observatory_grade TEXT,
            scan_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await?;

    // Create archive table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scan_archive (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            grade TEXT NOT NULL,
            ssl_labs_grade TEXT,
            mozilla_observatory_grade TEXT,
            scan_time DATETIME NOT NULL,
            certificate_summary TEXT,
            protocols_summary TEXT,   
            key_vulnerabilities TEXT
        )
        "#,
    )
    .execute(pool)
    .await?;

    println!("Database tables created/verified successfully");
    Ok(())
}

// =============================================================
// SCAN OPERATIONS

pub async fn get_recent_scan(
    pool: &SqlitePool,
    domain: &str,
) -> Result<Option<ScanRecord>, sqlx::Error> {
    sqlx::query_as::<_, ScanRecord>(
        r#"
        SELECT * FROM scan_records 
        WHERE domain = ? AND scan_time > datetime('now', '-7 days')
        ORDER BY scan_time DESC 
        LIMIT 1
        "#,
    )
    .bind(domain)
    .fetch_optional(pool)
    .await
}

pub async fn insert_scan(
    pool: &SqlitePool,
    domain: &str,
    grade: &str,
    ssl_labs_grade: Option<&str>,
    mozilla_observatory_grade: Option<&str>,
    ssl_labs_scan_time: Option<f64>,
    mozilla_scan_time: Option<f64>,
    tls_scan_time: Option<f64>,
    total_scan_time: Option<f64>, // NEW: Total user experience time
    ssl_labs_error: Option<&str>,
    mozilla_error: Option<&str>,
    tls_error: Option<&str>,
) -> Result<(), sqlx::Error> {
    // Insert into main scan_records table
    sqlx::query(
        r#"
        INSERT INTO scan_records (
            domain, grade, scan_time,
            ssl_labs_grade, mozilla_observatory_grade,
            ssl_labs_scan_time, mozilla_scan_time, tls_scan_time, total_scan_time,
            ssl_labs_error, mozilla_error, tls_error
        ) VALUES (?, ?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(domain)
    .bind(grade)
    .bind(ssl_labs_grade)
    .bind(mozilla_observatory_grade)
    .bind(ssl_labs_scan_time)
    .bind(mozilla_scan_time)
    .bind(tls_scan_time)
    .bind(total_scan_time)
    .bind(ssl_labs_error)
    .bind(mozilla_error)
    .bind(tls_error)
    .execute(pool)
    .await?;

    // Insert into grade history
    sqlx::query(
        r#"
        INSERT INTO domain_grade_history (
            domain, grade, ssl_labs_grade, mozilla_observatory_grade, scan_time
        ) VALUES (?, ?, ?, ?, datetime('now'))
        "#,
    )
    .bind(domain)
    .bind(grade)
    .bind(ssl_labs_grade)
    .bind(mozilla_observatory_grade)
    .execute(pool)
    .await?;

    Ok(())
}

// ==========================================
// MAINTENANCE OPERATIONS

pub async fn cleanup_old_scans(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Archive old records
    let archived = sqlx::query(
        r#"
        INSERT INTO scan_archive (
            domain, grade, ssl_labs_grade, mozilla_observatory_grade, 
            scan_time, certificate_summary, 
            protocols_summary, key_vulnerabilities
        )
        SELECT 
            domain, grade, ssl_labs_grade, mozilla_observatory_grade, 
            scan_time,
            'Certificate data archived',
            'Protocol data archived',
            'Vulnerability data archived'
        FROM scan_records 
        WHERE scan_time < datetime('now', '-7 days')
        "#,
    )
    .execute(pool)
    .await?;

    // Delete old records from cache
    let deleted =
        sqlx::query("DELETE FROM scan_records WHERE scan_time < datetime('now', '-7 days')")
            .execute(pool)
            .await?;

    println!(
        "Archived {} records, deleted {} from cache",
        archived.rows_affected(),
        deleted.rows_affected()
    );
    Ok(())
}

// ==============================
// ANALYTICS & TIMELINE

pub async fn get_domain_security_timeline(
    pool: &SqlitePool,
    domain: &str,
    limit: Option<i32>,
) -> Result<Vec<SecurityTimelineEntry>, sqlx::Error> {
    let limit_clause = limit.map(|l| format!("LIMIT {}", l)).unwrap_or_default();

    let query = format!(
        r#"
        SELECT scan_time, grade, ssl_labs_grade, mozilla_observatory_grade, 
               certificate_summary, protocols_summary, key_vulnerabilities
        FROM scan_archive WHERE domain = ?
        UNION ALL
        SELECT scan_time, grade, ssl_labs_grade, mozilla_observatory_grade,
               'Recent scan' as certificate_summary,
               'Recent scan' as protocols_summary,
               'Recent scan' as key_vulnerabilities
        FROM scan_records WHERE domain = ?
        ORDER BY scan_time DESC {}
        "#,
        limit_clause
    );

    sqlx::query_as::<_, SecurityTimelineEntry>(&query)
        .bind(domain)
        .bind(domain)
        .fetch_all(pool)
        .await
}

pub async fn get_grade_trend(
    pool: &SqlitePool,
    domain: &str,
) -> Result<Vec<(String, String, Option<String>, Option<String>)>, sqlx::Error> {
    let records = sqlx::query(
        r#"
        SELECT scan_time, grade, ssl_labs_grade, mozilla_observatory_grade 
        FROM domain_grade_history 
        WHERE domain = ? 
        ORDER BY scan_time ASC
        "#,
    )
    .bind(domain)
    .fetch_all(pool)
    .await?;

    Ok(records
        .into_iter()
        .map(|row| {
            let scan_time: String = row.get("scan_time");
            let grade: String = row.get("grade");
            let ssl_labs_grade: Option<String> = row.get("ssl_labs_grade");
            let mozilla_grade: Option<String> = row.get("mozilla_observatory_grade");
            (scan_time, grade, ssl_labs_grade, mozilla_grade)
        })
        .collect())
}

// ======================================
// DATABASE VERIFICATION

pub async fn verify_database_structure(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Check if tables exist and have correct structure
    let tables = sqlx::query("SELECT name FROM sqlite_master WHERE type='table'")
        .fetch_all(pool)
        .await?;

    println!("Existing database tables:");
    for table in tables {
        let table_name: String = table.get("name");
        println!("  - {}", table_name);
    }

    // Verify scan_records table structure
    let columns = sqlx::query("PRAGMA table_info(scan_records)")
        .fetch_all(pool)
        .await;

    match columns {
        Ok(cols) => {
            println!(
                "scan_records table structure verified ({} columns)",
                cols.len()
            );
        }
        Err(_) => {
            println!("scan_records table not found or invalid structure");
        }
    }

    Ok(())
}

// ======================================
// HIGH-LEVEL HANDLER

pub async fn handle_scan_request(
    pool: &SqlitePool,
    domain: String,
    grade: String,
    ssl_labs_grade: Option<String>,
    mozilla_observatory_grade: Option<String>,
    ssl_labs_scan_time: Option<f64>,
    mozilla_scan_time: Option<f64>,
    tls_scan_time: Option<f64>,
    total_scan_time: Option<f64>, // NEW
    ssl_labs_error: Option<String>,
    mozilla_error: Option<String>,
    tls_error: Option<String>,
) {
    match insert_scan(
        pool,
        &domain,
        &grade,
        ssl_labs_grade.as_deref(),
        mozilla_observatory_grade.as_deref(),
        ssl_labs_scan_time,
        mozilla_scan_time,
        tls_scan_time,
        total_scan_time,
        ssl_labs_error.as_deref(),
        mozilla_error.as_deref(),
        tls_error.as_deref(),
    )
    .await
    {
        Ok(_) => println!("Database insert successful for {}", domain),
        Err(e) => println!("Database insert failed for {}: {:?}", domain, e),
    }
}
