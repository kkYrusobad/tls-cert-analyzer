//! Subject Alternative Name (SAN) analysis

use super::{Finding, Severity};
use crate::cert::ParsedCertificate;
use crate::error::Result;

/// Analyzer for SAN-related issues
pub struct SanAnalyzer;

impl SanAnalyzer {
    /// Create new SAN analyzer
    pub fn new() -> Self {
        Self
    }

    /// Analyze certificate for SAN issues
    pub fn analyze(&self, cert: &ParsedCertificate) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for missing SAN extension (CN-only certificates are deprecated)
        if cert.subject_alt_names.is_empty() {
            findings.push(Finding {
                severity: Severity::Medium,
                title: "Missing Subject Alternative Names".to_string(),
                description: "Certificate relies on Common Name (CN) only. SANs are required by modern standards".to_string(),
                remediation: Some("Re-issue certificate with SAN extension".to_string()),
            });
        }

        Ok(findings)
    }
}

impl Default for SanAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{ValidityPeriod, PublicKeyInfo};
    use chrono::Utc;

    fn mock_cert_with_sans(sans: Vec<String>) -> ParsedCertificate {
        ParsedCertificate {
            subject: "CN=example.com".to_string(),
            issuer: "Test CA".to_string(),
            validity: ValidityPeriod {
                not_before: Utc::now(),
                not_after: Utc::now() + chrono::Duration::days(365),
            },
            public_key: PublicKeyInfo {
                algorithm: "RSA".to_string(),
                key_size_or_curve: "2048".to_string(),
            },
            signature_algorithm: "SHA256withRSA".to_string(),
            subject_alt_names: sans,
            is_ca: false,
            serial_number: "123".to_string(),
            fingerprint: "abc".to_string(),
            raw_der: vec![],
        }
    }

    #[test]
    fn test_missing_san() {
        let analyzer = SanAnalyzer::new();
        let cert = mock_cert_with_sans(vec![]);

        let findings = analyzer.analyze(&cert).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn test_with_san() {
        let analyzer = SanAnalyzer::new();
        let cert = mock_cert_with_sans(vec!["example.com".to_string()]);

        let findings = analyzer.analyze(&cert).unwrap();
        assert_eq!(findings.len(), 0);
    }
}
