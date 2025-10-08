//! Utility functions for VEFAS types
//!
//! This module provides no_std compatible utility functions for formatting
//! and string manipulation without using the format! macro.

use alloc::string::{String, ToString};

/// Format a number as hexadecimal without using format! macro
pub fn format_hex(value: u16, width: usize) -> String {
    let mut result = String::new();
    let hex_chars = b"0123456789abcdef";

    for i in (0..width).rev() {
        let nibble = ((value >> (i * 4)) & 0xF) as usize;
        result.push(hex_chars[nibble] as char);
    }

    result
}

/// Format a number as decimal without using format! macro
pub fn format_decimal(value: usize) -> String {
    if value == 0 {
        return "0".to_string();
    }

    let mut result = String::new();
    let mut n = value;

    while n > 0 {
        result.push((b'0' + (n % 10) as u8) as char);
        n /= 10;
    }

    // Reverse the string
    result.chars().rev().collect()
}

/// Format a number as decimal with sign for signed integers
pub fn format_signed_decimal(value: i32) -> String {
    if value == 0 {
        return "0".to_string();
    }

    let mut result = String::new();
    let mut n = if value < 0 {
        (-value) as usize
    } else {
        value as usize
    };

    while n > 0 {
        result.push((b'0' + (n % 10) as u8) as char);
        n /= 10;
    }

    // Reverse the numeric part
    let numeric_part: String = result.chars().rev().collect();

    if value < 0 {
        "-".to_string() + &numeric_part
    } else {
        numeric_part
    }
}

/// Format NamedGroup debug representation without using format! macro
pub fn format_named_group_debug(group: &crate::tls::NamedGroup) -> String {
    match group {
        crate::tls::NamedGroup::Secp256r1 => "Secp256r1".to_string(),
        crate::tls::NamedGroup::Secp384r1 => "Secp384r1".to_string(),
        crate::tls::NamedGroup::Secp521r1 => "Secp521r1".to_string(),
        crate::tls::NamedGroup::X25519 => "X25519".to_string(),
        crate::tls::NamedGroup::X448 => "X448".to_string(),
    }
}

/// Format CipherSuite debug representation without using format! macro
pub fn format_cipher_suite_debug(suite: &crate::tls::CipherSuite) -> String {
    match suite {
        crate::tls::CipherSuite::Aes128GcmSha256 => "Aes128GcmSha256".to_string(),
        crate::tls::CipherSuite::Aes256GcmSha384 => "Aes256GcmSha384".to_string(),
        crate::tls::CipherSuite::ChaCha20Poly1305Sha256 => "ChaCha20Poly1305Sha256".to_string(),
    }
}

/// Format TlsVersion debug representation without using format! macro
pub fn format_tls_version_debug(version: &crate::tls::TlsVersion) -> String {
    match version {
        crate::tls::TlsVersion::V1_3 => "V1_3".to_string(),
    }
}

/// Format HttpMethod debug representation without using format! macro
pub fn format_http_method_debug(method: &crate::http::HttpMethod) -> String {
    match method {
        crate::http::HttpMethod::Get => "Get".to_string(),
        crate::http::HttpMethod::Post => "Post".to_string(),
        crate::http::HttpMethod::Put => "Put".to_string(),
        crate::http::HttpMethod::Delete => "Delete".to_string(),
        crate::http::HttpMethod::Head => "Head".to_string(),
        crate::http::HttpMethod::Options => "Options".to_string(),
        crate::http::HttpMethod::Patch => "Patch".to_string(),
        crate::http::HttpMethod::Trace => "Trace".to_string(),
        crate::http::HttpMethod::Connect => "Connect".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_hex() {
        assert_eq!(format_hex(0x1234, 4), "1234");
        assert_eq!(format_hex(0x00AB, 4), "00ab");
        assert_eq!(format_hex(0x0001, 4), "0001");
    }

    #[test]
    fn test_format_decimal() {
        assert_eq!(format_decimal(0), "0");
        assert_eq!(format_decimal(123), "123");
        assert_eq!(format_decimal(1000), "1000");
        assert_eq!(format_decimal(999999), "999999");
    }

    #[test]
    fn test_format_signed_decimal() {
        assert_eq!(format_signed_decimal(0), "0");
        assert_eq!(format_signed_decimal(123), "123");
        assert_eq!(format_signed_decimal(-123), "-123");
        assert_eq!(format_signed_decimal(-1000), "-1000");
    }
}
