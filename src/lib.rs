//! TLS Certificate Analyzer Library
//!
//! This library provides comprehensive TLS certificate analysis capabilities,
//! including fetching, parsing, validating, and auditing X.509 certificates.
//!
//! # Examples
//!
//! ```no_run
//! use tls_cert_analyzer::{CertificateFetcher, CertificateAnalyzer};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Fetch certificate from a host
//!     let fetcher = CertificateFetcher::new();
//!     let chain = fetcher.fetch("google.com", 443).await?;
//!     
//!     // Analyze the certificate
//!     let analyzer = CertificateAnalyzer::new();
//!     let results = analyzer.analyze(&chain)?;
//!     
//!     println!("Analysis results: {:?}", results);
//!     Ok(())
//! }
//! ```
//!
//! # Architecture
//!
//! The library is organized into several modules:
//!
//! - `cert`: Certificate fetching and parsing
//! - `analysis`: Security analysis (expiry, weak crypto, SANs)
//! - `output`: Result formatting (JSON, table, text)
//! - `error`: Error types and handling
//!
//! # Graduate-Level Learning Objectives
//!
//! This implementation demonstrates:
//!
//! 1. **X.509 and PKI**: Understanding of certificate structure and validation
//! 2. **Async Rust**: Tokio runtime for concurrent network operations
//! 3. **Error Handling**: Type-safe error handling with thiserror
//! 4. **Security Analysis**: Detection of cryptographic weaknesses
//! 5. **API Design**: Clean, composable library interface

// Ensure we're using the 2021 edition features
#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

// Public modules
pub mod cert;
pub mod analysis;
pub mod output;
pub mod error;

// Re-export commonly used types
pub use error::{CertAnalyzerError, Result};

// Re-export main types from submodules for convenience
pub use cert::{CertificateFetcher, ParsedCertificate};
pub use analysis::{CertificateAnalyzer, AnalysisResult, Finding, Severity};
pub use output::{OutputFormat, OutputFormatter};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default connection timeout in seconds
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// Default near-expiry threshold in days
pub const DEFAULT_EXPIRY_WARNING_DAYS: i64 = 30;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
