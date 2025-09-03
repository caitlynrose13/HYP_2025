use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingAnalysis {
    pub is_suspicious: bool,
    pub risk_score: u32, // 0-100
    pub detected_patterns: Vec<String>,
    pub content_warnings: Vec<String>,
    pub domain_warnings: Vec<String>,
    pub recommendation: PhishingRecommendation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PhishingRecommendation {
    Safe,     // 0-30
    Caution,  // 31-60
    HighRisk, // 61-80
    Block,    // 81-100
}

// Add a small-risk list of TLDs that are frequently abused (low weight)
const SUSPICIOUS_TLDS: &[&str] = &[
    "shop", "xyz", "top", "work", "gq", "tk", "ml", "cf", "ga", "pw", "click", "monster",
];

// Simple whitelist of major sites that should never be flagged
const SAFE_DOMAINS: &[&str] = &[
    "google.com",
    "gmail.com",
    "mail.google.com",
    "facebook.com",
    "instagram.com",
    "www.instagram.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "ebay.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "github.com",
    "stackoverflow.com",
    "reddit.com",
    "youtube.com",
    "netflix.com",
    "spotify.com",
    "dropbox.com",
    "slack.com",
];

pub fn analyze_for_phishing(domain: &str, page_content: Option<&str>) -> PhishingAnalysis {
    // STEP 1: Check if it's a known safe domain
    if is_safe_domain(domain) {
        return PhishingAnalysis {
            is_suspicious: false,
            risk_score: 0,
            detected_patterns: vec!["Verified legitimate service".to_string()],
            content_warnings: vec![],
            domain_warnings: vec![],
            recommendation: PhishingRecommendation::Safe,
        };
    }

    let mut risk_score = 0u32;
    let mut warnings = Vec::new();

    // STEP 2: Domain-level checks
    let domain_lower = domain.to_lowercase();

    // Suspicious TLD (small weight)
    if let Some(tld) = domain_lower.rsplit('.').next() {
        if SUSPICIOUS_TLDS.contains(&tld) {
            risk_score += 10;
            warnings.push(format!("Suspicious TLD .{}", tld));
        }
    }

    // Very long domains (likely suspicious)
    if domain_lower.len() > 60 {
        risk_score += 20;
        warnings.push("Unusually long domain".to_string());
    } else if domain_lower.len() > 35 {
        risk_score += 10;
        warnings.push("Long domain".to_string());
    }

    // Heavy tracking URL (keep if full URL is provided)
    if domain_lower.contains('?') && domain_lower.matches('&').count() >= 3 {
        risk_score += 10;
        warnings.push("Tracker-style query parameters".to_string());
    }

    // Known suspicious keywords in domain
    if domain_lower.contains("secure-update")
        || domain_lower.contains("account-verify")
        || domain_lower.contains("login-check")
        || domain_lower.contains("paypal-verify")
        || domain_lower.contains("bank-security")
    {
        risk_score += 40;
        warnings.push("Suspicious domain keywords".to_string());
    }

    // STEP 3: Page content checks (if content provided)
    if let Some(content) = page_content {
        let content_lower = content.to_lowercase();

        // Strong scam / urgency phrases
        let strong_phrases = [
            "you have won",
            "congratulations winner",
            "claim your prize",
            "urgent action required",
            "account suspended",
            "verify immediately",
            "expires today",
            "limited time offer",
            "act now or lose",
            "reward",
            "gift card",
            "prize",
            "start survey",
            "survey",
            "attention!",
            "offer expires",
        ];
        let strong_hits = strong_phrases
            .iter()
            .filter(|p| content_lower.contains(*p))
            .count();

        if strong_hits >= 3 {
            risk_score += 50;
            warnings.push("Multiple strong scam phrases detected".to_string());
        } else if strong_hits >= 1 {
            risk_score += 25;
            warnings.push("Scam phrase detected".to_string());
        }

        // Countdown / timer hints
        let has_countdown = content_lower.contains("expires in") ||
            content_lower.contains("offer expires in") ||
            content_lower.contains("expires today") ||
            content_lower.contains("countdown") ||
            // simple mm:ss pattern
            Regex::new(r"\b\d{1,2}:\d{2}\b").ok()
                .map(|re| re.is_match(&content_lower))
                .unwrap_or(false);

        if has_countdown {
            risk_score += 10;
            warnings.push("Countdown/timer urgency".to_string());
        }

        // Excessive excitement
        let exclamation_count = content.matches('!').count();
        if exclamation_count > 20 {
            risk_score += 15;
            warnings.push("Excessive exclamation marks".to_string());
        }
    }

    // STEP 4: Cap and classify
    risk_score = std::cmp::min(risk_score, 100);

    let recommendation = match risk_score {
        0..=30 => PhishingRecommendation::Safe,
        31..=60 => PhishingRecommendation::Caution,
        61..=80 => PhishingRecommendation::HighRisk,
        _ => PhishingRecommendation::Block,
    };

    let is_suspicious = risk_score > 50;

    PhishingAnalysis {
        is_suspicious,
        risk_score,
        detected_patterns: warnings.clone(),
        content_warnings: warnings.clone(),
        domain_warnings: vec![],
        recommendation,
    }
}

fn is_safe_domain(domain: &str) -> bool {
    let domain_lower = domain.to_lowercase();

    SAFE_DOMAINS.iter().any(|&safe_domain| {
        domain_lower == safe_domain || domain_lower.ends_with(&format!(".{}", safe_domain))
    })
}

impl PhishingAnalysis {
    pub fn grade_impact(&self) -> (crate::services::security_grader::Grade, String) {
        use crate::services::security_grader::Grade;

        match self.recommendation {
            PhishingRecommendation::Safe => (Grade::A, "No phishing concerns".to_string()),
            PhishingRecommendation::Caution => (
                Grade::B,
                format!("Minor phishing indicators ({}%)", self.risk_score),
            ),
            PhishingRecommendation::HighRisk => (
                Grade::C,
                format!("High phishing risk ({}%)", self.risk_score),
            ),
            PhishingRecommendation::Block => (
                Grade::F,
                format!("Phishing site detected ({}%)", self.risk_score),
            ),
        }
    }

    pub fn should_override_grade(&self) -> bool {
        self.risk_score > 70 // Only override for very high risk
    }
}
