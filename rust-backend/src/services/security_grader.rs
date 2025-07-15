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
    pub cipher_is_strong: bool,
    pub cert_valid: bool,
    pub hsts: bool,
}

pub fn grade_site(input: &GradeInput) -> Grade {
    if !input.tls12_supported && !input.tls13_supported {
        return Grade::F;
    }
    if !input.cert_valid {
        return Grade::C;
    }
    if !input.cipher_is_strong {
        return Grade::B;
    }
    if input.tls13_supported && input.hsts {
        return Grade::APlus;
    }
    if input.tls13_supported {
        return Grade::A;
    }
    if input.tls12_supported {
        return Grade::AMinus;
    }
    Grade::F
}
