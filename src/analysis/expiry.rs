//! Certificate expiry analysis

use super::{Finding, Severity};
use crate::cert::ParsedCertificate;
use crate::error::Result;

/// Analyzer for certificate expiry issues
pub struct ExpiryAnalyzer {
    /// Warning threshold in days
    warning_threshold_days: i64,
}

impl ExpiryAnalyzer {
    /// Create new expiry analyzer with default thresholds
    pub fn new() -> Self {
        Self {
            warning_threshold_days: crate::DEFAULT_EXPIRY_WARNING_DAYS,
        }
    }

    /// Analyze certificate for expiry issues
    pub fn analyze(&self, cert: &ParsedCertificate) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check if expired
        if cert.validity.is_expired() {
            findings.push(Finding {
                severity: Severity::Critical,
                title: "Certificate Expired".to_string(),
                description: format!(
                    "Certificate expired on {}",
                    cert.validity.not_after.format("%Y-%m-%d %H:%M:%S UTC")
                ),
                remediation: Some("Renew the certificate immediately".to_string()),
            });
        }
        // Check if not yet valid
        else if cert.validity.is_not_yet_valid() {
            findings.push(Finding {
                severity: Severity::Critical,
                title: "Certificate Not Yet Valid".to_string(),
                description: format!(
                    "Certificate will not be valid until {}",
                    cert.validity.not_before.format("%Y-%m-%d %H:%M:%S UTC")
                ),
                remediation: Some("Check system time or wait for validity period".to_string()),
            });
        }
        // Check for near expiry
        else {
            let days_remaining = cert.validity.days_until_expiry();
            
            if days_remaining <= self.warning_threshold_days {
                let severity = match days_remaining {
                    0..=7 => Severity::High,
                    8..=30 => Severity::Medium,
                    _ => Severity::Low,
                };

                findings.push(Finding {
                    severity,
                    title: format!("Certificate Expires Soon ({days_remaining} days)"),
                    description: format!(
                        "Certificate will expire on {} ({days_remaining} days remaining)",
                        cert.validity.not_after.format("%Y-%m-%d")
                    ),
                    remediation: Some("Renew certificate before expiry".to_string()),
                });
            }
        }

        Ok(findings)
    }
}

impl Default for ExpiryAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crate::cert::{ValidityPeriod, PublicKeyInfo};

    fn mock_cert_with_validity(not_before: chrono::DateTime<Utc>, not_after: chrono::DateTime<Utc>) -> ParsedCertificate {
        ParsedCertificate {
            subject: "Test".to_string(),
            issuer: "Test CA".to_string(),
            validity: ValidityPeriod { not_before, not_after },
            public_key: PublicKeyInfo {
                algorithm: "RSA".to_string(),
                key_size_or_curve: "2048".to_string(),
            },
            signature_algorithm: "SHA256withRSA".to_string(),
            subject_alt_names: vec![],
            is_ca: false,
            serial_number: "123".to_string(),
            fingerprint: "abc".to_string(),
            raw_der: vec![],
        }
    }

    #[test]
    fn test_expired_certificate() {
        let analyzer = ExpiryAnalyzer::new();
        let cert = mock_cert_with_validity(
            Utc::now() - chrono::Duration::days(60),
            Utc::now() - chrono::Duration::days(1),
        );

        let findings = analyzer.analyze(&cert).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].title.contains("Expired"));
    }

    #[test]
    fn test_valid_certificate() {
        let analyzer = ExpiryAnalyzer::new();
        let cert = mock_cert_with_validity(
            Utc::now() - chrono::Duration::days(30),
            Utc::now() + chrono::Duration::days(365),
        );

        let findings = analyzer.analyze(&cert).unwrap();
        assert_eq!(findings.len(), 0);
    }
}
