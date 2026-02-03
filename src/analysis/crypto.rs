//! Cryptographic strength analysis

use super::{Finding, Severity};
use crate::cert::ParsedCertificate;
use crate::error::Result;

/// Analyzer for cryptographic strength issues
#[derive(Clone)]
pub struct CryptoAnalyzer;

impl CryptoAnalyzer {
    /// Create new crypto analyzer
    pub fn new() -> Self {
        Self
    }

    /// Analyze certificate for weak cryptography
    pub fn analyze(&self, cert: &ParsedCertificate) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check signature algorithm
        findings.extend(self.check_signature_algorithm(&cert.signature_algorithm));

        // Check public key strength
        findings.extend(self.check_public_key(&cert.public_key));

        Ok(findings)
    }

    /// Check signature algorithm for known weaknesses
    fn check_signature_algorithm(&self, algorithm: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let algo_lower = algorithm.to_lowercase();

        if algo_lower.contains("md5") {
            findings.push(Finding {
                severity: Severity::Critical,
                title: "Weak Signature Algorithm: MD5".to_string(),
                description: "MD5 is cryptographically broken and should not be used".to_string(),
                remediation: Some("Re-issue certificate with SHA-256 or better".to_string()),
            });
        } else if algo_lower.contains("sha1") || algo_lower.contains("sha-1") {
            findings.push(Finding {
                severity: Severity::High,
                title: "Deprecated Signature Algorithm: SHA-1".to_string(),
                description: "SHA-1 is deprecated and vulnerable to collision attacks".to_string(),
                remediation: Some("Re-issue certificate with SHA-256 or better".to_string()),
            });
        }

        findings
    }

    /// Check public key strength
    fn check_public_key(&self, key_info: &crate::cert::PublicKeyInfo) -> Vec<Finding> {
        let mut findings = Vec::new();
        let algo_lower = key_info.algorithm.to_lowercase();

        if algo_lower.contains("rsa") {
            // Parse key size
            if let Ok(key_size) = key_info.key_size_or_curve.parse::<u32>() {
                if key_size < 2048 {
                    findings.push(Finding {
                        severity: Severity::High,
                        title: format!("Weak RSA Key Size: {key_size} bits"),
                        description: "RSA keys smaller than 2048 bits are considered weak".to_string(),
                        remediation: Some("Use at least 2048-bit RSA keys (4096 recommended)".to_string()),
                    });
                } else if key_size > 4096 {
                    findings.push(Finding {
                        severity: Severity::Info,
                        title: format!("Very Large RSA Key: {key_size} bits"),
                        description: "Keys larger than 4096 bits offer diminishing security returns".to_string(),
                        remediation: None,
                    });
                }
            }
        } else if algo_lower.contains("dsa") {
            findings.push(Finding {
                severity: Severity::High,
                title: "Deprecated Algorithm: DSA".to_string(),
                description: "DSA is deprecated in favor of RSA or ECDSA".to_string(),
                remediation: Some("Use RSA (2048+ bits) or ECDSA (P-256+)".to_string()),
            });
        }

        findings
    }
}

impl Default for CryptoAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_detection() {
        let analyzer = CryptoAnalyzer::new();
        let findings = analyzer.check_signature_algorithm("MD5withRSA");
        
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_sha1_detection() {
        let analyzer = CryptoAnalyzer::new();
        let findings = analyzer.check_signature_algorithm("SHA1withRSA");
        
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn test_sha256_ok() {
        let analyzer = CryptoAnalyzer::new();
        let findings = analyzer.check_signature_algorithm("SHA256withRSA");
        
        assert_eq!(findings.len(), 0);
    }
}
