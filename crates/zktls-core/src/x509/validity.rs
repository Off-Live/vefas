//! Certificate validity period parsing for X.509 certificates
//!
//! This module implements validity period parsing according to RFC 5280.
//! Handles both UTCTime and GeneralizedTime formats.

use crate::asn1::{DerParser, DerValue, tag};
use super::{X509Error, X509Result};

/// Certificate validity period
/// 
/// Based on RFC 5280 Validity structure:
/// ```asn1
/// Validity ::= SEQUENCE {
///      notBefore      Time,
///      notAfter       Time }
/// 
/// Time ::= CHOICE {
///      utcTime        UTCTime,
///      generalTime    GeneralizedTime }
/// ```
#[derive(Debug, Clone)]
pub struct Validity {
    /// Certificate not valid before this time (Unix timestamp)
    not_before: u64,
    
    /// Certificate not valid after this time (Unix timestamp) 
    not_after: u64,
}

impl Validity {
    /// Parse certificate validity from ASN.1 DER
    pub fn parse(validity_value: &DerValue) -> X509Result<Self> {
        if !validity_value.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidValidity);
        }
        
        let mut seq_iter = DerParser::parse_sequence(validity_value.content, 1)?;
        
        // Parse notBefore
        let not_before_item = seq_iter.next()
            .ok_or(X509Error::MissingRequiredField("notBefore"))??;
            
        let not_before = Self::parse_time(&not_before_item)?;
        
        // Parse notAfter
        let not_after_item = seq_iter.next()
            .ok_or(X509Error::MissingRequiredField("notAfter"))??;
            
        let not_after = Self::parse_time(&not_after_item)?;
        
        // Validate that notAfter > notBefore
        if not_after <= not_before {
            return Err(X509Error::InvalidValidity);
        }
        
        Ok(Validity {
            not_before,
            not_after,
        })
    }
    
    /// Parse ASN.1 Time (UTCTime or GeneralizedTime)
    fn parse_time(time_item: &DerValue) -> X509Result<u64> {
        if time_item.tag.matches(tag::UTC_TIME) {
            Self::parse_utc_time(time_item.content)
        } else if time_item.tag.matches(tag::GENERALIZED_TIME) {
            Self::parse_generalized_time(time_item.content)
        } else {
            Err(X509Error::InvalidValidity)
        }
    }
    
    /// Parse UTCTime (YYMMDDHHMMSSZ or YYMMDDHHMMSS+HHMM)
    /// 
    /// RFC 5280: For dates between 1950 and 2049, UTCTime is used.
    /// Years 50-99 represent 1950-1999, years 00-49 represent 2000-2049.
    fn parse_utc_time(data: &[u8]) -> X509Result<u64> {
        // Convert to string for parsing
        let time_str = core::str::from_utf8(data)
            .map_err(|_| X509Error::InvalidValidity)?;
        
        // Basic format validation (YYMMDDHHMMSSZ)
        if time_str.len() != 13 || !time_str.ends_with('Z') {
            return Err(X509Error::InvalidValidity);
        }
        
        let time_digits = &time_str[..12];
        
        // Parse components
        let year_2digit: u32 = time_digits[0..2].parse()
            .map_err(|_| X509Error::InvalidValidity)?;
        let month: u32 = time_digits[2..4].parse()
            .map_err(|_| X509Error::InvalidValidity)?;
        let day: u32 = time_digits[4..6].parse()
            .map_err(|_| X509Error::InvalidValidity)?;
        let hour: u32 = time_digits[6..8].parse()
            .map_err(|_| X509Error::InvalidValidity)?;
        let minute: u32 = time_digits[8..10].parse()
            .map_err(|_| X509Error::InvalidValidity)?;
        let second: u32 = time_digits[10..12].parse()
            .map_err(|_| X509Error::InvalidValidity)?;
        
        // Convert 2-digit year to 4-digit year
        let year = if year_2digit >= 50 {
            1900 + year_2digit
        } else {
            2000 + year_2digit
        };
        
        // Basic validation
        if !(1..=12).contains(&month) || 
           !(1..=31).contains(&day) ||
           hour >= 24 ||
           minute >= 60 ||
           second >= 60 {
            return Err(X509Error::InvalidValidity);
        }
        
        // Convert to Unix timestamp (simplified calculation)
        // This is a basic implementation - a full implementation would handle
        // leap years, varying month lengths, etc.
        let timestamp = Self::datetime_to_timestamp(year, month, day, hour, minute, second)?;
        
        Ok(timestamp)
    }
    
    /// Parse GeneralizedTime (YYYYMMDDHHMMSSZ or YYYYMMDDHHMMSS+HHMM)
    fn parse_generalized_time(data: &[u8]) -> X509Result<u64> {
        // Convert to string for parsing
        let time_str = core::str::from_utf8(data)
            .map_err(|_| X509Error::InvalidValidity)?;
        
        // Basic format validation (YYYYMMDDHHMMSSZ)
        if time_str.len() != 15 || !time_str.ends_with('Z') {
            return Err(X509Error::InvalidValidity);
        }
        
        let time_digits = &time_str[..14];
        
        // Parse components
        let year: u32 = time_digits[0..4].parse()
            .map_err(|_| X509Error::InvalidValidity)?;
        let month: u32 = time_digits[4..6].parse()
            .map_err(|_| X509Error::InvalidValidity)?;
        let day: u32 = time_digits[6..8].parse()
            .map_err(|_| X509Error::InvalidValidity)?;
        let hour: u32 = time_digits[8..10].parse()
            .map_err(|_| X509Error::InvalidValidity)?;
        let minute: u32 = time_digits[10..12].parse()
            .map_err(|_| X509Error::InvalidValidity)?;
        let second: u32 = time_digits[12..14].parse()
            .map_err(|_| X509Error::InvalidValidity)?;
        
        // Basic validation
        if year < 1970 ||
           !(1..=12).contains(&month) || 
           !(1..=31).contains(&day) ||
           hour >= 24 ||
           minute >= 60 ||
           second >= 60 {
            return Err(X509Error::InvalidValidity);
        }
        
        // Convert to Unix timestamp
        let timestamp = Self::datetime_to_timestamp(year, month, day, hour, minute, second)?;
        
        Ok(timestamp)
    }
    
    /// Convert date/time components to Unix timestamp
    /// 
    /// This is a simplified implementation for demonstration.
    /// A production implementation would use a proper date/time library.
    fn datetime_to_timestamp(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> X509Result<u64> {
        if year < 1970 {
            return Err(X509Error::InvalidValidity);
        }
        
        // Simplified calculation - doesn't handle leap years properly
        // Days since Unix epoch (1970-01-01)
        let mut days = 0u64;
        
        // Add days for complete years
        for y in 1970..year {
            days += if Self::is_leap_year(y) { 366 } else { 365 };
        }
        
        // Add days for complete months in current year
        let days_in_month = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        for m in 1..month {
            days += days_in_month[(m - 1) as usize] as u64;
            
            // Handle February in leap years
            if m == 2 && Self::is_leap_year(year) {
                days += 1;
            }
        }
        
        // Add remaining days
        days += (day - 1) as u64;
        
        // Convert to seconds and add time components
        let timestamp = days * 86400 + // 24 * 60 * 60
                       (hour as u64) * 3600 + // 60 * 60
                       (minute as u64) * 60 +
                       second as u64;
        
        Ok(timestamp)
    }
    
    /// Check if a year is a leap year
    fn is_leap_year(year: u32) -> bool {
        (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
    }
    
    /// Get not-before timestamp
    pub fn not_before(&self) -> u64 {
        self.not_before
    }
    
    /// Get not-after timestamp
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
    
    /// Check if certificate is currently valid
    pub fn is_valid_at(&self, timestamp: u64) -> bool {
        timestamp >= self.not_before && timestamp <= self.not_after
    }
    
    /// Check if certificate is currently valid (using current system time)
    /// 
    /// Note: In zkVM environments, this would need to use a trusted timestamp
    #[cfg(feature = "std")]
    pub fn is_currently_valid(&self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
            
        self.is_valid_at(current_time)
    }
}