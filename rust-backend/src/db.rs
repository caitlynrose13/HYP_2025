use crate::AppState;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Row, SqlitePool};

// ===============================================
// DATABASE MODELS

#[derive(Debug, FromRow, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: i64,
    pub domain: String,
    pub scanned_by: String,
    pub grade: String,
    // NEW: Individual service grades
    pub ssl_labs_grade: Option<String>,
    pub mozilla_observatory_grade: Option<String>,
    pub tls_analyzer_grade: Option<String>,
    pub ssl_labs_scan_time: Option<f64>,
    pub mozilla_scan_time: Option<f64>,
    pub tls_scan_time: Option<f64>,
    pub ssl_labs_error: Option<String>,
    pub mozilla_error: Option<String>,
    pub tls_error: Option<String>,
    // Existing fields
    pub scan_time: String,
    pub certificate_json: String,
    pub protocols_json: String,
    pub cipher_suites_json: String,
    pub vulnerabilities_json: String,
    pub key_exchange_json: String,
    pub explanation: Option<String>,
    pub tls_scan_duration: Option<String>,
    pub details_json: String,
    pub is_phishing_detected: Option<bool>,
    pub phishing_risk_score: Option<i32>,
    pub phishing_warning_message: Option<String>,
}

#[derive(Debug, FromRow, Serialize)]
pub struct SecurityTimelineEntry {
    pub scan_time: String,
    pub grade: String,
    pub ssl_labs_grade: Option<String>,
    pub mozilla_observatory_grade: Option<String>,
    pub tls_analyzer_grade: Option<String>,
    pub certificate_summary: Option<String>,
    pub protocols_summary: Option<String>,
    pub key_vulnerabilities: Option<String>,
}

// ======================================================
// DATABASE INITIALIZATION

pub async fn init_db(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scan_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            scanned_by TEXT NOT NULL,
            grade TEXT NOT NULL,
            -- NEW: Individual service grades and timings
            ssl_labs_grade TEXT,
            mozilla_observatory_grade TEXT,
            tls_analyzer_grade TEXT,
            ssl_labs_scan_time REAL,
            mozilla_scan_time REAL,
            tls_scan_time REAL,
            ssl_labs_error TEXT,
            mozilla_error TEXT,
            tls_error TEXT,
            -- Existing fields
            scan_time DATETIME NOT NULL,
            certificate_json TEXT NOT NULL,
            protocols_json TEXT NOT NULL,
            cipher_suites_json TEXT NOT NULL,
            vulnerabilities_json TEXT NOT NULL,
            key_exchange_json TEXT NOT NULL,
            explanation TEXT,
            tls_scan_duration TEXT,
            details_json TEXT NOT NULL,
            is_phishing_detected BOOLEAN,
            phishing_risk_score INTEGER,
            phishing_warning_message TEXT
        );
        
        CREATE TABLE IF NOT EXISTS domain_grade_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            grade TEXT NOT NULL,
            ssl_labs_grade TEXT,
            mozilla_observatory_grade TEXT,
            tls_analyzer_grade TEXT,
            scan_time DATETIME NOT NULL,
            is_phishing_detected BOOLEAN
        );
        
        CREATE TABLE IF NOT EXISTS scan_archive (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            grade TEXT NOT NULL,
            ssl_labs_grade TEXT,
            mozilla_observatory_grade TEXT,
            tls_analyzer_grade TEXT,
            scan_time DATETIME NOT NULL,
            certificate_summary TEXT,
            protocols_summary TEXT,   
            key_vulnerabilities TEXT,
            explanation TEXT,
            is_phishing_detected BOOLEAN,
            phishing_risk_score INTEGER
        );
        "#,
    )
    .execute(pool)
    .await?;
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
    scanned_by: &str,
    grade: &str,
    // NEW: Individual service results
    ssl_labs_grade: Option<&str>,
    mozilla_observatory_grade: Option<&str>,
    tls_analyzer_grade: Option<&str>,
    ssl_labs_scan_time: Option<f64>,
    mozilla_scan_time: Option<f64>,
    tls_scan_time: Option<f64>,
    ssl_labs_error: Option<&str>,
    mozilla_error: Option<&str>,
    tls_error: Option<&str>,
    // Existing parameters
    certificate_json: &str,
    protocols_json: &str,
    cipher_suites_json: &str,
    vulnerabilities_json: &str,
    key_exchange_json: &str,
    explanation: Option<&str>,
    tls_scan_duration: Option<&str>,
    details_json: &str,
    is_phishing_detected: Option<bool>,
    phishing_risk_score: Option<i32>,
    phishing_warning_message: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO scan_records (
            domain, scanned_by, grade, scan_time,
            ssl_labs_grade, mozilla_observatory_grade, tls_analyzer_grade,
            ssl_labs_scan_time, mozilla_scan_time, tls_scan_time,
            ssl_labs_error, mozilla_error, tls_error,
            certificate_json, protocols_json, cipher_suites_json,
            vulnerabilities_json, key_exchange_json, explanation, 
            tls_scan_duration, details_json,
            is_phishing_detected, phishing_risk_score, phishing_warning_message
        ) VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(domain)
    .bind(scanned_by)
    .bind(grade)
    .bind(ssl_labs_grade)
    .bind(mozilla_observatory_grade)
    .bind(tls_analyzer_grade)
    .bind(ssl_labs_scan_time)
    .bind(mozilla_scan_time)
    .bind(tls_scan_time)
    .bind(ssl_labs_error)
    .bind(mozilla_error)
    .bind(tls_error)
    .bind(certificate_json)
    .bind(protocols_json)
    .bind(cipher_suites_json)
    .bind(vulnerabilities_json)
    .bind(key_exchange_json)
    .bind(explanation)
    .bind(tls_scan_duration)
    .bind(details_json)
    .bind(is_phishing_detected)
    .bind(phishing_risk_score)
    .bind(phishing_warning_message)
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO domain_grade_history (
            domain, grade, ssl_labs_grade, mozilla_observatory_grade, 
            tls_analyzer_grade, scan_time, is_phishing_detected
        ) VALUES (?, ?, ?, ?, ?, datetime('now'), ?)
        "#,
    )
    .bind(domain)
    .bind(grade)
    .bind(ssl_labs_grade)
    .bind(mozilla_observatory_grade)
    .bind(tls_analyzer_grade)
    .bind(is_phishing_detected)
    .execute(pool)
    .await?;

    Ok(())
}

// ==========================================
// MAINTENANCE OPERATIONS

pub async fn cleanup_old_scans(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    let archived = sqlx::query(
        r#"
        INSERT INTO scan_archive (
            domain, grade, ssl_labs_grade, mozilla_observatory_grade, 
            tls_analyzer_grade, scan_time, certificate_summary, 
            protocols_summary, key_vulnerabilities, explanation, 
            is_phishing_detected, phishing_risk_score
        )
        SELECT 
            domain, grade, ssl_labs_grade, mozilla_observatory_grade, 
            tls_analyzer_grade, scan_time,
            CASE 
                WHEN certificate_json LIKE '%"common_name"%' THEN 
                    json_extract(certificate_json, '$.common_name') || ' (expires: ' || json_extract(certificate_json, '$.valid_to') || ')'
                ELSE 'Certificate data available'
            END,
            CASE
                WHEN protocols_json LIKE '%"tls_1_3":"Supported"%' AND protocols_json LIKE '%"tls_1_2":"Supported"%' THEN 'TLS1.2,TLS1.3'
                WHEN protocols_json LIKE '%"tls_1_3":"Supported"%' THEN 'TLS1.3'
                WHEN protocols_json LIKE '%"tls_1_2":"Supported"%' THEN 'TLS1.2'
                ELSE 'Legacy TLS'
            END,
            CASE
                WHEN vulnerabilities_json LIKE '%"Vulnerable"%' THEN 'Has vulnerabilities'
                ELSE 'No known vulnerabilities'
            END,
            explanation,
            is_phishing_detected,
            phishing_risk_score
        FROM scan_records 
        WHERE scan_time < datetime('now', '-7 days')
        "#,
    )
    .execute(pool)
    .await?;

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
               tls_analyzer_grade, certificate_summary, protocols_summary, key_vulnerabilities
        FROM scan_archive WHERE domain = ?
        UNION ALL
        SELECT scan_time, grade, ssl_labs_grade, mozilla_observatory_grade, 
               tls_analyzer_grade,
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
) -> Result<
    Vec<(
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    )>,
    sqlx::Error,
> {
    let records = sqlx::query(
        r#"
        SELECT scan_time, grade, ssl_labs_grade, mozilla_observatory_grade, tls_analyzer_grade 
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
            let tls_grade: Option<String> = row.get("tls_analyzer_grade");
            (scan_time, grade, ssl_labs_grade, mozilla_grade, tls_grade)
        })
        .collect())
}

// ======================================
// HIGH-LEVEL HANDLER

pub async fn handle_scan_request(
    state: &AppState,
    domain: String,
    scanned_by: String,
    grade: String,
    // NEW: Individual service results
    ssl_labs_grade: Option<String>,
    mozilla_observatory_grade: Option<String>,
    tls_analyzer_grade: Option<String>,
    ssl_labs_scan_time: Option<f64>,
    mozilla_scan_time: Option<f64>,
    tls_scan_time: Option<f64>,
    ssl_labs_error: Option<String>,
    mozilla_error: Option<String>,
    tls_error: Option<String>,
    // Existing parameters
    certificate_json: String,
    protocols_json: String,
    cipher_suites_json: String,
    vulnerabilities_json: String,
    key_exchange_json: String,
    explanation: Option<String>,
    scan_duration_str: String,
    details_json: String,
    is_phishing_detected: Option<bool>,
    phishing_risk_score: Option<i32>,
    phishing_warning_message: Option<String>,
) {
    match insert_scan(
        &state.pool,
        &domain,
        &scanned_by,
        &grade,
        ssl_labs_grade.as_deref(),
        mozilla_observatory_grade.as_deref(),
        tls_analyzer_grade.as_deref(),
        ssl_labs_scan_time,
        mozilla_scan_time,
        tls_scan_time,
        ssl_labs_error.as_deref(),
        mozilla_error.as_deref(),
        tls_error.as_deref(),
        &certificate_json,
        &protocols_json,
        &cipher_suites_json,
        &vulnerabilities_json,
        &key_exchange_json,
        explanation.as_deref(),
        Some(&scan_duration_str),
        &details_json,
        is_phishing_detected,
        phishing_risk_score,
        phishing_warning_message.as_deref(),
    )
    .await
    {
        Ok(_) => println!("Database insert successful for {}", domain),
        Err(e) => println!("Database insert failed for {}: {:?}", domain, e),
    }
}
