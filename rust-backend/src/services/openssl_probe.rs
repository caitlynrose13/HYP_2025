use openssl::ssl::{SslConnector, SslVerifyMode, SslVersion};
use std::net::TcpStream;

pub fn test_tls10(domain: &str) -> bool {
    let mut builder = SslConnector::builder(openssl::ssl::SslMethod::tls()).unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1))
        .unwrap();
    builder
        .set_max_proto_version(Some(SslVersion::TLS1))
        .unwrap();
    let connector = builder.build();
    let stream = TcpStream::connect((domain, 443));
    if let Ok(stream) = stream {
        let mut config = connector.configure().unwrap().verify_hostname(false);
        config.set_verify(SslVerifyMode::NONE);
        let ssl = config.connect(domain, stream);
        let supported = ssl.is_ok();
        println!("TLS 1.0 support for {}: {}", domain, supported);
        supported
    } else {
        println!("TLS 1.0 connection failed for {}", domain);
        false
    }
}

pub fn test_tls11(domain: &str) -> bool {
    let mut builder = SslConnector::builder(openssl::ssl::SslMethod::tls()).unwrap();
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_1))
        .unwrap();
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_1))
        .unwrap();
    let connector = builder.build();
    let stream = TcpStream::connect((domain, 443));
    if let Ok(stream) = stream {
        let mut config = connector.configure().unwrap().verify_hostname(false);
        config.set_verify(SslVerifyMode::NONE);
        let ssl = config.connect(domain, stream);
        let supported = ssl.is_ok();
        println!("TLS 1.1 support for {}: {}", domain, supported);
        supported
    } else {
        println!("TLS 1.1 connection failed for {}", domain);
        false
    }
}
