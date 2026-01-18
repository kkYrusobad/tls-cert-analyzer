//! Certificate parser
//!
//! Parses X.509 certificates from DER-encoded format.
//!
//! # X.509 Structure (Simplified)
//!
//! ```text
//! Certificate ::= SEQUENCE {
//!     tbsCertificate       TBSCertificate,
//!     signatureAlgorithm   AlgorithmIdentifier,
//!     signatureValue       BIT STRING
//! }
//!
//! TBSCertificate ::= SEQUENCE {
//!     version              [0] EXPLICIT Version DEFAULT v1,
//!     serialNumber         CertificateSerialNumber,
//!     signature            AlgorithmIdentifier,
//!     issuer               Name,
//!     validity             Validity,
//!     subject              Name,
//!     subjectPublicKeyInfo SubjectPublicKeyInfo,
//!     extensions           [3] EXPLICIT Extensions OPTIONAL
//! }
//! ```

use crate::error::{CertAnalyzerError, Result};
use chrono::{DateTime, Utc};

/// Parsed X.509 certificate with all relevant fields
///
/// This structure contains the parsed fields from an X.509 certificate
/// that are most relevant for security analysis.
#[derive(Debug, Clone)]
pub struct ParsedCertificate {
    /// Certificate subject (who the cert is for)
    pub subject: String,
    
    /// Certificate issuer (who signed the cert)
    pub issuer: String,
    
    /// Validity period
    pub validity: ValidityPeriod,
    
    /// Public key information
    pub public_key: PublicKeyInfo,
    
    /// Signature algorithm used to sign this certificate
    pub signature_algorithm: String,
    
    /// Subject Alternative Names (DNS names, IPs, emails)
    pub subject_alt_names: Vec<String>,
    
    /// Whether this is a CA certificate
    pub is_ca: bool,
    
    /// Serial number (as hex string)
    pub serial_number: String,
    
    /// SHA-256 fingerprint of the certificate
    pub fingerprint: String,
    
    /// Raw DER-encoded certificate bytes
    pub raw_der: Vec<u8>,
}

/// Certificate validity period
#[derive(Debug, Clone)]
pub struct ValidityPeriod {
    /// Not valid before this time
    pub not_before: DateTime<Utc>,
    
    /// Not valid after this time
    pub not_after: DateTime<Utc>,
}

impl ValidityPeriod {
    /// Check if the certificate is currently valid
    pub fn is_currently_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }

    /// Check if the certificate is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }

    /// Check if the certificate is not yet valid
    pub fn is_not_yet_valid(&self) -> bool {
        Utc::now() < self.not_before
    }

    /// Days until expiry (negative if expired)
    pub fn days_until_expiry(&self) -> i64 {
        let now = Utc::now();
        (self.not_after - now).num_days()
    }
}

/// Public key information
#[derive(Debug, Clone)]
pub struct PublicKeyInfo {
    /// Algorithm (RSA, ECDSA, Ed25519, etc.)
    pub algorithm: String,
    
    /// Key size in bits (for RSA) or curve name (for ECDSA)
    pub key_size_or_curve: String,
}

/// Parse a DER-encoded X.509 certificate
///
/// # Arguments
///
/// * `der_bytes` - Raw DER-encoded certificate bytes
///
/// # Errors
///
/// Returns error if certificate is malformed or cannot be parsed
///
/// # Examples
///
/// ```ignore
/// // Example with actual DER-encoded certificate bytes
/// // Note: parse_certificate is not publicly exported yet
/// // This will be available after the parser module is completed
/// let der_bytes: &[u8] = &[]; // Would contain actual certificate data
/// // let cert = parse_certificate(der_bytes)?;
/// // println!("Subject: {}", cert.subject);
/// ```
pub fn parse_certificate(_der_bytes: &[u8]) -> Result<ParsedCertificate> {
    // TODO: Implement full X.509 parsing using x509-parser crate
    // This is a placeholder that demonstrates the structure
    
    // For now, return error indicating implementation is pending
    Err(CertAnalyzerError::ParseError(
        "X.509 parsing not yet implemented - coming in next phase".to_string()
    ))
    
    // Real implementation will:
    // 1. Use x509_parser::parse_x509_certificate()
    // 2. Extract all relevant fields
    // 3. Parse extensions (SANs, basic constraints, key usage)
    // 4. Calculate fingerprint
    // 5. Return ParsedCertificate
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_validity_period_current() {
        let validity = ValidityPeriod {
            not_before: Utc::now() - Duration::days(30),
            not_after: Utc::now() + Duration::days(30),
        };
        
        assert!(validity.is_currently_valid());
        assert!(!validity.is_expired());
        assert!(!validity.is_not_yet_valid());
    }

    #[test]
    fn test_validity_period_expired() {
        let validity = ValidityPeriod {
            not_before: Utc::now() - Duration::days(60),
            not_after: Utc::now() - Duration::days(30),
        };
        
        assert!(!validity.is_currently_valid());
        assert!(validity.is_expired());
        assert!(!validity.is_not_yet_valid());
        assert!(validity.days_until_expiry() < 0);
    }

    #[test]
    fn test_validity_period_not_yet_valid() {
        let validity = ValidityPeriod {
            not_before: Utc::now() + Duration::days(10),
            not_after: Utc::now() + Duration::days(40),
        };
        
        assert!(!validity.is_currently_valid());
        assert!(!validity.is_expired());
        assert!(validity.is_not_yet_valid());
    }
}
