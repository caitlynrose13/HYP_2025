use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingAnalysis {
    pub is_suspicious: bool,
    pub risk_score: u32, // 0-100, higher = more suspicious
    pub detected_patterns: Vec<PhishingPattern>,
    pub content_warnings: Vec<String>,
    pub domain_warnings: Vec<String>,
    pub recommendation: PhishingRecommendation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingPattern {
    pub pattern_type: String,
    pub description: String,
    pub severity: PhishingSeverity,
    pub detected_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PhishingSeverity {
    Low,      // 5-15 points
    Medium,   // 15-30 points
    High,     // 30-50 points
    Critical, // 50+ points
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PhishingRecommendation {
    Safe,             // 0-20 points
    Caution,          // 21-40 points
    HighRisk,         // 41-70 points
    BlockImmediately, // 71+ points
}

impl PhishingSeverity {
    fn score(&self) -> u32 {
        match self {
            PhishingSeverity::Low => 10,
            PhishingSeverity::Medium => 25,
            PhishingSeverity::High => 40,
            PhishingSeverity::Critical => 60,
        }
    }
}

// Compiled regex patterns for efficiency
static URGENCY_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(
            r"(?i)\b(attention|urgent|immediate|act now|limited time|expires? (today|soon|in))\b",
        )
        .unwrap(),
        Regex::new(r"(?i)\b(claim (now|immediately)|don't miss out|last chance|final notice)\b")
            .unwrap(),
        Regex::new(r"(?i)\b(congratulations|you('ve| have) won|winner|selected|chosen)\b").unwrap(),
        Regex::new(r"(?i)\b(verify (your|account)|update (your|account)|suspended|locked)\b")
            .unwrap(),
        Regex::new(r"(?i)\b(click here|start survey|download now|get started)\b").unwrap(),
    ]
});

static REWARD_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)\b(free|gift|prize|reward|bonus|offer|discount)\b").unwrap(),
        Regex::new(r"(?i)\$([\d,]+)\.?\d*\s*(worth|value|offer|prize)").unwrap(),
        Regex::new(r"(?i)r([\d,]+)\.?\d*\s*(worth|value|offer|prize)").unwrap(), // South African Rand
        Regex::new(r"(?i)\b(\d+%\s*off|save \$?\d+|up to \d+)\b").unwrap(),
    ]
});

static SURVEY_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)\b(survey|questionnaire|feedback|short survey|quick survey)\b").unwrap(),
        Regex::new(r"(?i)\b(take this survey|complete.*survey|answer.*questions)\b").unwrap(),
        Regex::new(r"(?i)\b(customer satisfaction|experience|opinion|review)\b").unwrap(),
    ]
});

static BRAND_IMPERSONATION: Lazy<HashMap<&str, Vec<&str>>> = Lazy::new(|| {
    let mut brands = HashMap::new();
    brands.insert("builders", vec!["warehouse", "depot", "supply", "center"]);
    brands.insert("amazon", vec!["prime", "aws", "kindle"]);
    brands.insert("microsoft", vec!["office", "outlook", "xbox", "windows"]);
    brands.insert("apple", vec!["iphone", "ipad", "itunes", "app store"]);
    brands.insert("google", vec!["gmail", "youtube", "android", "chrome"]);
    brands.insert("paypal", vec!["payment", "money", "transfer"]);
    brands.insert("bank", vec!["account", "security", "card", "payment"]);
    brands.insert("netflix", vec!["subscription", "movie", "series"]);
    brands.insert("facebook", vec!["meta", "instagram", "whatsapp"]);
    brands.insert("delivery", vec!["package", "shipment", "courier", "postal"]);
    brands
});

static SUSPICIOUS_DOMAINS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i).*-?(security|secure|verification|update|support)-?.*").unwrap(),
        Regex::new(r"(?i).*-?(account|login|signin|auth|verify)-?.*").unwrap(),
        Regex::new(r"(?i).*-?(survey|offer|prize|winner|claim)-?.*").unwrap(),
        Regex::new(r"(?i).*\.(tk|ml|ga|cf|gq)$").unwrap(), // Suspicious TLDs
        Regex::new(r"(?i).*\d{4,}.*").unwrap(),            // Domains with many numbers
    ]
});

// Common typos and misspellings used in phishing
static TYPOSQUATTING_PATTERNS: Lazy<Vec<(Regex, &str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r"(?i)succesful|sucess|sucessful").unwrap(),
            "successful",
        ), // succesfulart.shop
        (Regex::new(r"(?i)amazom|amazoon|amaz0n").unwrap(), "amazon"),
        (Regex::new(r"(?i)payp4l|payp@l|paypaI").unwrap(), "paypal"),
        (Regex::new(r"(?i)g00gle|googIe|g0ogle").unwrap(), "google"),
        (
            Regex::new(r"(?i)microsft|mircosoft|micr0soft").unwrap(),
            "microsoft",
        ),
        (Regex::new(r"(?i)appIe|app1e|appl3").unwrap(), "apple"),
        (
            Regex::new(r"(?i)faceb00k|facebook|facebok").unwrap(),
            "facebook",
        ),
        (
            Regex::new(r"(?i)netf1ix|netfIix|netfl1x").unwrap(),
            "netflix",
        ),
        (
            Regex::new(r"(?i)buil|build3rs|bui1ders").unwrap(),
            "builders",
        ),
        (
            Regex::new(r"(?i)warehaus|ware-house|wareh0use").unwrap(),
            "warehouse",
        ),
        (
            Regex::new(r"(?i)secur1ty|security-|sec-ure").unwrap(),
            "security",
        ),
        (Regex::new(r"(?i)updat3|update-|up-date").unwrap(), "update"),
        (Regex::new(r"(?i)verif1|verify-|ver1fy").unwrap(), "verify"),
    ]
});

// Suspicious e-commerce and art-related patterns
static ECOMMERCE_SCAM_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i).*(art|gallery|shop|store|sale|deal|discount).*").unwrap(),
        Regex::new(r"(?i).*(cheap|free|best|top|exclusive|limited).*").unwrap(),
        Regex::new(r"(?i).*(outlet|warehouse|direct|factory).*").unwrap(),
        Regex::new(r"(?i).*(luxury|premium|designer|authentic).*").unwrap(),
    ]
});

pub fn analyze_for_phishing(domain: &str, page_content: Option<&str>) -> PhishingAnalysis {
    let mut risk_score = 0u32;
    let mut detected_patterns = Vec::new();
    let mut content_warnings = Vec::new();
    let mut domain_warnings = Vec::new();

    // Analyze domain for suspicious patterns
    analyze_domain_patterns(
        domain,
        &mut risk_score,
        &mut detected_patterns,
        &mut domain_warnings,
    );

    // Analyze page content if available
    if let Some(content) = page_content {
        analyze_content_patterns(
            content,
            &mut risk_score,
            &mut detected_patterns,
            &mut content_warnings,
        );
        analyze_brand_impersonation(
            domain,
            content,
            &mut risk_score,
            &mut detected_patterns,
            &mut content_warnings,
        );
    }

    let recommendation = match risk_score {
        0..=20 => PhishingRecommendation::Safe,
        21..=40 => PhishingRecommendation::Caution,
        41..=70 => PhishingRecommendation::HighRisk,
        _ => PhishingRecommendation::BlockImmediately,
    };

    PhishingAnalysis {
        is_suspicious: risk_score > 30,
        risk_score,
        detected_patterns,
        content_warnings,
        domain_warnings,
        recommendation,
    }
}

fn analyze_domain_patterns(
    domain: &str,
    risk_score: &mut u32,
    detected_patterns: &mut Vec<PhishingPattern>,
    domain_warnings: &mut Vec<String>,
) {
    let domain_lower = domain.to_lowercase();

    // Check for typosquatting (misspellings of known brands)
    for (pattern, intended_word) in TYPOSQUATTING_PATTERNS.iter() {
        if pattern.is_match(&domain_lower) {
            *risk_score += PhishingSeverity::Critical.score();
            detected_patterns.push(PhishingPattern {
                pattern_type: "Typosquatting".to_string(),
                description: format!("Domain appears to be a misspelling of '{}'", intended_word),
                severity: PhishingSeverity::Critical,
                detected_text: Some(domain.to_string()),
            });
            domain_warnings.push(format!(
                "Potential typosquatting of '{}': {}",
                intended_word, domain
            ));
        }
    }

    // Check for suspicious domain patterns
    for pattern in SUSPICIOUS_DOMAINS.iter() {
        if pattern.is_match(&domain_lower) {
            *risk_score += PhishingSeverity::Medium.score();
            detected_patterns.push(PhishingPattern {
                pattern_type: "Suspicious Domain Structure".to_string(),
                description: "Domain contains suspicious keywords commonly used in phishing"
                    .to_string(),
                severity: PhishingSeverity::Medium,
                detected_text: Some(domain.to_string()),
            });
            domain_warnings.push(format!("Suspicious domain pattern detected: {}", domain));
        }
    }

    // Check for e-commerce scam patterns
    let ecommerce_matches = ECOMMERCE_SCAM_PATTERNS
        .iter()
        .filter(|pattern| pattern.is_match(&domain_lower))
        .count();

    if ecommerce_matches >= 2 {
        *risk_score += PhishingSeverity::High.score();
        detected_patterns.push(PhishingPattern {
            pattern_type: "E-commerce Scam Pattern".to_string(),
            description:
                "Domain uses multiple e-commerce keywords often associated with scam sites"
                    .to_string(),
            severity: PhishingSeverity::High,
            detected_text: Some(domain.to_string()),
        });
        domain_warnings.push(format!(
            "Multiple e-commerce scam indicators in domain: {}",
            domain
        ));
    } else if ecommerce_matches == 1 {
        *risk_score += PhishingSeverity::Low.score();
        detected_patterns.push(PhishingPattern {
            pattern_type: "E-commerce Domain".to_string(),
            description:
                "Domain appears to be e-commerce related - requires additional verification"
                    .to_string(),
            severity: PhishingSeverity::Low,
            detected_text: Some(domain.to_string()),
        });
    }

    // Check for homograph attacks (lookalike domains)
    if contains_unicode_lookalikes(&domain_lower) {
        *risk_score += PhishingSeverity::High.score();
        detected_patterns.push(PhishingPattern {
            pattern_type: "Homograph Attack".to_string(),
            description: "Domain uses unicode characters that mimic legitimate brands".to_string(),
            severity: PhishingSeverity::High,
            detected_text: Some(domain.to_string()),
        });
        domain_warnings.push("Domain uses suspicious unicode characters".to_string());
    }

    // Check domain length and complexity
    if domain_lower.len() > 50 || domain_lower.matches('.').count() > 4 {
        *risk_score += PhishingSeverity::Low.score();
        detected_patterns.push(PhishingPattern {
            pattern_type: "Suspicious Domain Length".to_string(),
            description: "Unusually long or complex domain name".to_string(),
            severity: PhishingSeverity::Low,
            detected_text: Some(domain.to_string()),
        });
    }

    // Check for unusual TLD combinations with suspicious keywords
    if domain_lower.ends_with(".shop")
        && (domain_lower.contains("art") || domain_lower.contains("gallery"))
    {
        *risk_score += PhishingSeverity::Medium.score();
        detected_patterns.push(PhishingPattern {
            pattern_type: "Suspicious TLD/Keyword Combo".to_string(),
            description:
                "Art/gallery site using .shop domain - common pattern in counterfeit goods scams"
                    .to_string(),
            severity: PhishingSeverity::Medium,
            detected_text: Some(domain.to_string()),
        });
        domain_warnings.push(
            "Art/gallery + .shop domain combination is often used for counterfeit goods"
                .to_string(),
        );
    }
}

fn analyze_content_patterns(
    content: &str,
    risk_score: &mut u32,
    detected_patterns: &mut Vec<PhishingPattern>,
    content_warnings: &mut Vec<String>,
) {
    let content_lower = content.to_lowercase();

    // Check for urgency patterns (like "Attention!", "expires today")
    for pattern in URGENCY_PATTERNS.iter() {
        if let Some(matches) = pattern.find(&content_lower) {
            *risk_score += PhishingSeverity::High.score();
            detected_patterns.push(PhishingPattern {
                pattern_type: "Urgency Tactics".to_string(),
                description: "Uses urgency language to pressure immediate action".to_string(),
                severity: PhishingSeverity::High,
                detected_text: Some(matches.as_str().to_string()),
            });
            content_warnings.push(format!("Urgency language detected: '{}'", matches.as_str()));
        }
    }

    // Check for reward/prize patterns
    for pattern in REWARD_PATTERNS.iter() {
        if let Some(matches) = pattern.find(&content_lower) {
            *risk_score += PhishingSeverity::Medium.score();
            detected_patterns.push(PhishingPattern {
                pattern_type: "Reward/Prize Offer".to_string(),
                description: "Offers unrealistic rewards or prizes".to_string(),
                severity: PhishingSeverity::Medium,
                detected_text: Some(matches.as_str().to_string()),
            });
            content_warnings.push(format!("Suspicious reward offer: '{}'", matches.as_str()));
        }
    }

    // Check for survey patterns
    for pattern in SURVEY_PATTERNS.iter() {
        if let Some(matches) = pattern.find(&content_lower) {
            *risk_score += PhishingSeverity::Medium.score();
            detected_patterns.push(PhishingPattern {
                pattern_type: "Survey Scam".to_string(),
                description: "Uses survey pretense to collect personal information".to_string(),
                severity: PhishingSeverity::Medium,
                detected_text: Some(matches.as_str().to_string()),
            });
            content_warnings.push(format!("Survey scam pattern: '{}'", matches.as_str()));
        }
    }

    // Check for excessive exclamation marks and caps
    let exclamation_count = content.matches('!').count();
    let caps_ratio =
        content.chars().filter(|c| c.is_uppercase()).count() as f32 / content.len() as f32;

    if exclamation_count > 5 || caps_ratio > 0.3 {
        *risk_score += PhishingSeverity::Low.score();
        detected_patterns.push(PhishingPattern {
            pattern_type: "Aggressive Typography".to_string(),
            description: "Excessive use of capital letters and exclamation marks".to_string(),
            severity: PhishingSeverity::Low,
            detected_text: None,
        });
        content_warnings.push("Aggressive typography patterns detected".to_string());
    }
}

fn analyze_brand_impersonation(
    domain: &str,
    content: &str,
    risk_score: &mut u32,
    detected_patterns: &mut Vec<PhishingPattern>,
    content_warnings: &mut Vec<String>,
) {
    let domain_lower = domain.to_lowercase();
    let content_lower = content.to_lowercase();

    for (brand, keywords) in BRAND_IMPERSONATION.iter() {
        // Check if domain contains brand name but isn't official
        if domain_lower.contains(brand) && !is_likely_official_domain(domain, brand) {
            // Check if content also mentions brand keywords
            let keyword_matches = keywords
                .iter()
                .filter(|&keyword| content_lower.contains(keyword))
                .count();

            if keyword_matches > 0 {
                *risk_score += PhishingSeverity::Critical.score();
                detected_patterns.push(PhishingPattern {
                    pattern_type: "Brand Impersonation".to_string(),
                    description: format!("Appears to impersonate {} brand", brand),
                    severity: PhishingSeverity::Critical,
                    detected_text: Some(format!("Domain: {}, Brand: {}", domain, brand)),
                });
                content_warnings.push(format!("Potential {} brand impersonation detected", brand));
            }
        }
    }
}

fn contains_unicode_lookalikes(domain: &str) -> bool {
    // Common unicode characters used in homograph attacks
    let suspicious_chars = [
        'а', 'е', 'о', 'р', 'с', 'х', 'у', // Cyrillic lookalikes
        'ο', 'α', 'ρ', 'ε', // Greek lookalikes
        '0', '1', // Number lookalikes
    ];

    domain.chars().any(|c| suspicious_chars.contains(&c))
}

fn is_likely_official_domain(domain: &str, brand: &str) -> bool {
    let domain_lower = domain.to_lowercase();

    // Basic heuristic: official domains usually have brand as main domain
    // e.g., builders.co.za, amazon.com, not mybuilderssurvey.com
    match brand {
        "builders" => domain_lower == "builders.co.za" || domain_lower == "builders.com",
        "amazon" => domain_lower.starts_with("amazon.") && domain_lower.split('.').count() <= 3,
        "microsoft" => {
            domain_lower.starts_with("microsoft.") || domain_lower.starts_with("outlook.")
        }
        "google" => domain_lower.starts_with("google.") || domain_lower.starts_with("gmail."),
        "apple" => domain_lower.starts_with("apple.") || domain_lower.starts_with("icloud."),
        "paypal" => domain_lower.starts_with("paypal."),
        "netflix" => domain_lower.starts_with("netflix."),
        "facebook" => domain_lower.starts_with("facebook.") || domain_lower.starts_with("fb."),
        _ => false,
    }
}

impl PhishingAnalysis {
    pub fn grade_impact(&self) -> (crate::services::security_grader::Grade, String) {
        use crate::services::security_grader::Grade;

        match self.recommendation {
            PhishingRecommendation::Safe => {
                (Grade::A, "No phishing indicators detected".to_string())
            }
            PhishingRecommendation::Caution => (
                Grade::B,
                format!(
                    "Some phishing indicators detected (score: {})",
                    self.risk_score
                ),
            ),
            PhishingRecommendation::HighRisk => (
                Grade::F,
                format!(
                    "High risk phishing site detected (score: {})",
                    self.risk_score
                ),
            ),
            PhishingRecommendation::BlockImmediately => (
                Grade::F,
                format!(
                    "Critical phishing threat detected (score: {})",
                    self.risk_score
                ),
            ),
        }
    }

    pub fn should_override_grade(&self) -> bool {
        self.risk_score > 40 // High risk or critical
    }
}
