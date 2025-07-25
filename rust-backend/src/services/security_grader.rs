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
    // F - No TLS support or major security issues
    if !input.tls12_supported && !input.tls13_supported {
        return Grade::F;
    }

    // F - Supporting weak protocols (TLS 1.0/1.1) significantly downgrades
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
