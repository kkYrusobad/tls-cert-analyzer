/// Error types for TLS certificate analyzer
///
/// This module defines all error types used throughout the application.
/// We use `thiserror` for library errors to provide specific error types,
/// which makes error handling more explicit and type-safe.
use std::io;
use thiserror::Error;

/// Main error type for the certificate analyzer
///
/// This enum covers all possible errors that can occur during certificate
/// fetching, parsing, validation, and analysis operations.
#[derive(Debug, Error)]
pub enum CertAnalyzerError {
    /// Network-related errors (connection failures, timeouts, etc.)
    #[error("Network error: {0}")]
    Network(#[from] io::Error),

    /// TLS handshake failures
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),

    /// Certificate parsing errors (malformed ASN.1, invalid DER encoding)
    #[error("Certificate parsing error: {0}")]
    ParseError(String),

    /// Invalid certificate chain (broken chain, missing intermediate, etc.)
    #[error("Invalid certificate chain: {0}")]
    InvalidChain(String),

    /// Host not found or DNS resolution failed
    #[error("Host not found: {0}")]
    HostNotFound(String),

    /// Connection timeout
    #[error("Timeout connecting to {host}:{port} after {duration:?}")]
    Timeout {
        host: String,
        port: u16,
        duration: std::time::Duration,
    },

    /// Invalid input (hostname, port, etc.)
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Certificate validation error
    #[error("Certificate validation failed: {0}")]
    ValidationError(String),

    /// No certificates returned by server
    #[error("No certificates returned by server")]
    NoCertificates,

    /// File I/O error
    #[error("File I/O error: {0}")]
    FileError(String),

    /// Serialization error (JSON, table formatting, etc.)
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Specialized Result type for certificate analyzer operations
///
/// This is a convenience type alias that uses our custom error type.
pub type Result<T> = std::result::Result<T, CertAnalyzerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CertAnalyzerError::InvalidInput("test".to_string());
        assert_eq!(err.to_string(), "Invalid input: test");
    }

    #[test]
    fn test_timeout_error() {
        let err = CertAnalyzerError::Timeout {
            host: "example.com".to_string(),
            port: 443,
            duration: std::time::Duration::from_secs(10),
        };
        assert!(err.to_string().contains("example.com:443"));
    }
}
