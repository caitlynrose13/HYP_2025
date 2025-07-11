use rust_backend::services::tls_handshake::client_handshake::perform_tls_handshake_full;
use rust_backend::services::tls_handshake::client_handshake::{
    TlsSecurityLevel, probe_tls_security_level,
};
use rust_backend::services::tls_parser::TlsVersion;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use std::sync::Once;
use tokio::net::TcpListener; //TCP listener
use tracing::{Level, info};

static mut LOG_FILE: Option<Mutex<std::fs::File>> = None;
static INIT: Once = Once::new();

fn log_to_file(line: &str) {
    unsafe {
        INIT.call_once(|| {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open("handshake_debug.log")
                .expect("Unable to open log file");
            LOG_FILE = Some(Mutex::new(file));
        });
        if let Some(ref mutex) = LOG_FILE {
            let mut file = mutex.lock().unwrap();
            writeln!(file, "{}", line).ok();
        }
    }
}

macro_rules! log_both {
    ($($arg:tt)*) => {
        {
            let s = format!($($arg)*);
            println!("{}", s);
            log_to_file(&s);
        }
    };
}

#[tokio::main] // the program entry point using the Tokio async runtime.
async fn main() {
    dotenvy::dotenv().ok(); //loads environment variables

    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    // Replace println! with log_both! in top-level handshake calls for debug capture
    println!("=== TLS Security Level Assessment ===");
    // Only test the compatible TLS 1.2 endpoint
    let test_domains = vec!["tls-v1-2.badssl.com"];
    for domain in test_domains {
        println!("Probing {} for TLS security level...", domain);
        println!("    Testing TLS 1.2...");
        match perform_tls_handshake_full(domain, TlsVersion::TLS1_2) {
            Ok(_) => println!("    ✓ TLS 1.2 - SUPPORTED"),
            Err(e) => println!("    ✗ TLS 1.2 - FAILED: {:?}", e),
        }
    }

    println!("TLS 1.3 not yet implemented");

    // allow all origins and headers for now - NEED TO CHANGE LATER

    // Build Axum app
    //let app = Router::new().nest("/", routes::assessment_routes::router());

    //tcp listener at port 8080
    let _listener = TcpListener::bind("127.0.0.1:8080")
        .await
        .expect("Failed to bind to port 8080");

    println!("Server listening on http://127.0.0.1:8080");

    //axum::serve(listener, app).await.expect("Server error");
}
