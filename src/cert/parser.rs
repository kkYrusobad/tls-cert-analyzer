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
use x509_parser::public_key::PublicKey;

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
pub fn parse_certificate(der_bytes: &[u8]) -> Result<ParsedCertificate> {
    use x509_parser::prelude::*;
    use sha2::{Sha256, Digest};

    // Parse the X.509 certificate
    let (_, cert) = X509Certificate::from_der(der_bytes)
        .map_err(|e| CertAnalyzerError::ParseError(format!("Failed to parse DER: {e}")))?;

    // Extract subject
    let subject = cert.subject().to_string();

    // Extract issuer
    let issuer = cert.issuer().to_string();

    // Extract validity period
    let validity = ValidityPeriod {
        not_before: DateTime::from_timestamp(cert.validity().not_before.timestamp(), 0)
            .ok_or_else(|| CertAnalyzerError::ParseError("Invalid not_before timestamp".to_string()))?
            .into(),
        not_after: DateTime::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .ok_or_else(|| CertAnalyzerError::ParseError("Invalid not_after timestamp".to_string()))?
            .into(),
    };

    // Extract public key info
    let public_key = {
        let pk_info = cert.public_key();
        let algorithm = pk_info.algorithm.algorithm.to_id_string();

        let key_size_or_curve = if algorithm.contains("rsaEncryption") {
            // For RSA, extract key size
            if let Ok(key) = pk_info.parsed() {
                match key {
                    PublicKey::RSA(rsa_key) => {
                        // Key size in bits = modulus size in bytes * 8
                        format!("{}", rsa_key.key_size() * 8)
                    }
                    _ => "unknown".to_string(),
                }
            } else {
                "unknown".to_string()
            }
        } else if algorithm.contains("ecPublicKey") {
            // For ECDSA, extract curve name
            "P-256".to_string() // Simplified, real implementation would parse the curve
        } else {
            "unknown".to_string()
        };

        PublicKeyInfo {
            algorithm: if algorithm.contains("rsaEncryption") {
                "RSA".to_string()
            } else if algorithm.contains("ecPublicKey") {
                "ECDSA".to_string()
            } else {
                algorithm
            },
            key_size_or_curve,
        }
    };

    // Extract signature algorithm
    let signature_algorithm = cert.signature_algorithm.algorithm.to_id_string();

    // Extract Subject Alternative Names
    let mut subject_alt_names = Vec::new();
    if let Some(san_ext) = cert.extensions().iter().find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME) {
        if let ParsedExtension::SubjectAlternativeName(san) = san_ext.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => {
                        subject_alt_names.push(dns.to_string());
                    }
                    GeneralName::IPAddress(ip) => {
                        subject_alt_names.push(format!("{ip:?}"));
                    }
                    GeneralName::RFC822Name(email) => {
                        subject_alt_names.push(email.to_string());
                    }
                    _ => {}
                }
            }
        }
    }

    // Check if this is a CA certificate
    let is_ca = cert.extensions()
        .iter()
        .find(|e| e.oid == x509_parser::oid_registry::OID_X509_EXT_BASIC_CONSTRAINTS)
        .and_then(|ext| {
            if let ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
                Some(bc.ca)
            } else {
                None
            }
        })
        .unwrap_or(false);

    // Extract serial number as hex string
    let serial_number = cert.serial.to_str_radix(16);

    // Calculate SHA-256 fingerprint
    let mut hasher = Sha256::new();
    hasher.update(der_bytes);
    let fingerprint = format!("{:x}", hasher.finalize());

    Ok(ParsedCertificate {
        subject,
        issuer,
        validity,
        public_key,
        signature_algorithm,
        subject_alt_names,
        is_ca,
        serial_number,
        fingerprint,
        raw_der: der_bytes.to_vec(),
    })
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
