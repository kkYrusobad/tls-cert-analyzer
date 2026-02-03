//! Certificate security analysis module

mod expiry;
mod crypto;
mod san;

pub use self::expiry::ExpiryAnalyzer;
pub use self::crypto::CryptoAnalyzer;
pub use self::san::SanAnalyzer;

use crate::cert::ParsedCertificate;
use crate::error::Result;
use serde::{Deserialize, Serialize};

/// Security finding severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// Informational finding (no immediate risk)
    Info,
    /// Low severity (minor issue)
    Low,
    /// Medium severity (should be addressed)
    Medium,
    /// High severity (serious issue)
    High,
    /// Critical severity (immediate action required)
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A security finding from certificate analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Severity level
    pub severity: Severity,
    
    /// Short title
    pub title: String,
    
    /// Detailed description
    pub description: String,
    
    /// Remediation recommendation
    pub remediation: Option<String>,
}

/// Complete analysis results for a certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Certificate subject
    pub subject: String,
    
    /// All findings
    pub findings: Vec<Finding>,
    
    /// Overall risk score (0-100, higher is worse)
    pub risk_score: u8,
}

impl AnalysisResult {
    /// Check if there are any critical findings
    pub fn has_critical_findings(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Critical)
    }

    /// Get highest severity level
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

/// Main certificate analyzer
#[derive(Clone)]
pub struct CertificateAnalyzer {
    expiry: ExpiryAnalyzer,
    crypto: CryptoAnalyzer,
    san: SanAnalyzer,
}

impl CertificateAnalyzer {
    /// Create a new certificate analyzer with default settings
    pub fn new() -> Self {
        Self {
            expiry: ExpiryAnalyzer::new(),
            crypto: CryptoAnalyzer::new(),
            san: SanAnalyzer::new(),
        }
    }

    /// Analyze a certificate for security issues
    ///
    /// Runs all analysis modules and aggregates findings
    pub fn analyze(&self, cert: &ParsedCertificate) -> Result<AnalysisResult> {
        let mut findings = Vec::new();

        // Run all analyzers
        findings.extend(self.expiry.analyze(cert)?);
        findings.extend(self.crypto.analyze(cert)?);
        findings.extend(self.san.analyze(cert)?);

        // Calculate risk score based on findings
        let risk_score = Self::calculate_risk_score(&findings);

        Ok(AnalysisResult {
            subject: cert.subject.clone(),
            findings,
            risk_score,
        })
    }

    /// Calculate overall risk score from findings
    ///
    /// Formula: Sum of (severity weight * count)
    /// - Critical: 25 points each
    /// - High: 15 points each
    /// - Medium: 8 points each
    /// - Low: 3 points each
    /// - Info: 1 point each
    ///
    /// Capped at 100
    fn calculate_risk_score(findings: &[Finding]) -> u8 {
        let score: u32 = findings
            .iter()
            .map(|f| match f.severity {
                Severity::Critical => 25,
                Severity::High => 15,
                Severity::Medium => 8,
                Severity::Low => 3,
                Severity::Info => 1,
            })
            .sum();

        score.min(100) as u8
    }
}

impl Default for CertificateAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_risk_score_calculation() {
        let findings = vec![
            Finding {
                severity: Severity::Critical,
                title: "Test".to_string(),
                description: "Test".to_string(),
                remediation: None,
            },
            Finding {
                severity: Severity::High,
                title: "Test".to_string(),
                description: "Test".to_string(),
                remediation: None,
            },
        ];

        let score = CertificateAnalyzer::calculate_risk_score(&findings);
        assert_eq!(score, 40); // 25 + 15
    }

    #[test]
    fn test_risk_score_capped() {
        let findings: Vec<Finding> = (0..10)
            .map(|_| Finding {
                severity: Severity::Critical,
                title: "Test".to_string(),
                description: "Test".to_string(),
                remediation: None,
            })
            .collect();

        let score = CertificateAnalyzer::calculate_risk_score(&findings);
        assert_eq!(score, 100); // Capped at 100
    }
}
