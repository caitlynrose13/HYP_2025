use std::fs::{OpenOptions, File};
use std::io::{Read, Write};
use std::collections::HashMap;
use std::path::Path;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedScan {
    pub domain: String,
    pub grade: Grade,
    pub details: GradeInput,
}

const LOG_PATH: &str = "scan_log.json";

fn load_cache() -> HashMap<String, CachedScan> {
    if !Path::new(LOG_PATH).exists() {
        return HashMap::new();
    }
    let mut file = match File::open(LOG_PATH) {
        Ok(f) => f,
        Err(_) => return HashMap::new(),
    };
    let mut contents = String::new();
    if file.read_to_string(&mut contents).is_ok() {
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        HashMap::new()
    }
}

fn save_cache(cache: &HashMap<String, CachedScan>) {
    if let Ok(json) = serde_json::to_string_pretty(cache) {
        let _ = OpenOptions::new().write(true).create(true).truncate(true).open(LOG_PATH)
            .and_then(|mut f| f.write_all(json.as_bytes()));
    }
}

pub fn get_or_run_scan(domain: &str, input: &GradeInput) -> (Grade, bool) {
    let mut cache = load_cache();
    if let Some(cached) = cache.get(domain) {
        // Return cached result
        return (cached.grade, true);
    }
    let grade = grade_site(input);
    let entry = CachedScan {
        domain: domain.to_string(),
        grade,
        details: input.clone(),
    };
    cache.insert(domain.to_string(), entry);
    save_cache(&cache);
    (grade, false)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grade {
    APlus,
    A,
    AMinus,
    B,
    C,
    F,
}

#[derive(Debug, Clone)]
pub struct GradeInput {
    pub tls13_supported: bool,
    pub tls12_supported: bool,
    pub tls11_supported: bool,
    pub tls10_supported: bool,
    pub cipher_is_strong: bool,
    pub cert_valid: bool,
    pub hsts: bool,
    pub forward_secrecy: bool,
    pub weak_protocols_disabled: bool, // TLS 1.0/1.1 disabled
}

pub fn grade_site(input: &GradeInput) -> Grade {
    // F - No TLS 1.2 or 1.3 support, or weak protocols (SSL Labs: F)
    if !input.tls12_supported || !input.tls13_supported {
        // If either TLS 1.2 or TLS 1.3 fails, treat as supporting weak protocols
        return Grade::F;
    }
    if input.tls10_supported || input.tls11_supported {
        return Grade::F;
    }

    // C - Certificate issues (expired, invalid, etc.)
    if !input.cert_valid {
        return Grade::C;
    }

    // B - Weak cipher suites or no forward secrecy
    if !input.cipher_is_strong || !input.forward_secrecy {
        return Grade::B;
    }

    // A+ - TLS 1.3 + HSTS + strong ciphers + forward secrecy
    if input.tls13_supported
        && input.hsts
        && input.tls12_supported
        && input.cipher_is_strong
        && input.forward_secrecy
    {
        return Grade::APlus;
    }

    // A - TLS 1.3 supported with strong security features
    if input.tls13_supported
        && input.tls12_supported
        && input.cipher_is_strong
        && input.forward_secrecy
    {
        return Grade::A;
    }

    // A- - Only TLS 1.2 but with excellent security (strong ciphers, forward secrecy)
    if input.tls12_supported && input.cipher_is_strong && input.cert_valid && input.forward_secrecy
    {
        return Grade::AMinus;
    }

    // B - TLS 1.2 with some security features
    if input.tls12_supported && input.cert_valid {
        return Grade::B;
    }

    Grade::F
}
