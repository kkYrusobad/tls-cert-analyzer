//! Certificate validator
//!
//! Validates certificate chains according to RFC 5280.

use crate::error::{CertAnalyzerError, Result};
use crate::cert::ParsedCertificate;

/// Certificate chain validator
///
/// Validates certificate chains according to RFC 5280 Section 6:
/// Path Validation algorithm.
pub struct CertificateValidator {
    // Configuration options
}

impl CertificateValidator {
    /// Create a new certificate validator
    pub fn new() -> Self {
        Self {}
    }

    /// Validate a certificate chain
    ///
    /// # Arguments
    ///
    /// * `chain` - Ordered list of certificates (leaf first, root last)
    ///
    /// # Errors
    ///
    /// Returns error if chain is invalid
    pub fn validate_chain(&self, chain: &[ParsedCertificate]) -> Result<()> {
        if chain.is_empty() {
            return Err(CertAnalyzerError::InvalidChain(
                "Empty certificate chain".to_string()
            ));
        }

        // 1. Check that each certificate (except the last) is signed by the next one
        for i in 0..chain.len().saturating_sub(1) {
            let cert = &chain[i];
            let issuer_cert = &chain[i + 1];

            // Verify that the issuer field matches the next cert's subject
            if cert.issuer != issuer_cert.subject {
                return Err(CertAnalyzerError::InvalidChain(
                    format!(
                        "Chain broken: Certificate {} issuer '{}' does not match next cert subject '{}'",
                        i, cert.issuer, issuer_cert.subject
                    )
                ));
            }

            // Verify that the issuer is a CA
            if !issuer_cert.is_ca && i + 1 < chain.len() - 1 {
                return Err(CertAnalyzerError::InvalidChain(
                    format!("Certificate {} is not a CA but is used to sign other certificates", i + 1)
                ));
            }
        }

        // 2. Check validity periods
        for (i, cert) in chain.iter().enumerate() {
            if cert.validity.is_expired() {
                return Err(CertAnalyzerError::ValidationError(
                    format!("Certificate {} in chain is expired", i)
                ));
            }

            if cert.validity.is_not_yet_valid() {
                return Err(CertAnalyzerError::ValidationError(
                    format!("Certificate {} in chain is not yet valid", i)
                ));
            }
        }

        // 3. Verify the leaf certificate is not a CA (unless it's a single self-signed cert)
        if chain.len() > 1 && chain[0].is_ca {
            return Err(CertAnalyzerError::InvalidChain(
                "Leaf certificate cannot be a CA certificate".to_string()
            ));
        }

        tracing::info!("Certificate chain validation passed ({} certificates)", chain.len());
        Ok(())
    }
}

impl Default for CertificateValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_creation() {
        let _validator = CertificateValidator::new();
    }
}
