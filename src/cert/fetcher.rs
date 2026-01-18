//! Certificate fetcher
//!
//! This module implements TLS connection establishment and certificate retrieval.
//!
//! # Design Decisions
//!
//! We use `rustls` instead of OpenSSL for several reasons:
//! 1. Memory safety: Pure Rust implementation
//! 2. No C dependencies: Easier to build and audit
//! 3. Modern TLS: Focus on TLS 1.2+ only
//! 4. Learning value: Understand TLS internals without FFI complexity
//!
//! # TLS Handshake Flow
//!
//! ```text
//! Client                                  Server
//!   |                                       |
//!   | -------- ClientHello ---------------→ |
//!   |                                       |
//!   | ←------- ServerHello ---------------- |
//!   | ←------- Certificate ---------------- |  ← We extract this
//!   | ←------- ServerKeyExchange ---------- |
//!   | ←------- ServerHelloDone ------------ |
//!   |                                       |
//!   | -------- ClientKeyExchange ----------→ |
//!   | -------- ChangeCipherSpec -----------→ |
//!   | -------- Finished -------------------→ |
//!   |                                       |
//!   | ←------- ChangeCipherSpec ----------- |
//!   | ←------- Finished ------------------- |
//!   |                                       |
//! ```

use crate::error::{CertAnalyzerError, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use rustls::ClientConfig;
use rustls::RootCertStore;

/// Certificate fetcher that connects to TLS hosts and retrieves certificates
///
/// # Examples
///
/// ```no_run
/// use tls_cert_analyzer::CertificateFetcher;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let fetcher = CertificateFetcher::new();
///     let chain = fetcher.fetch("google.com", 443).await?;
///     println!("Retrieved {} certificates", chain.len());
///     Ok(())
/// }
/// ```
pub struct CertificateFetcher {
    /// Connection timeout
    timeout: Duration,
    /// TLS client configuration
    config: Arc<ClientConfig>,
}

impl CertificateFetcher {
    /// Create a new certificate fetcher with default settings
    ///
    /// Default timeout: 10 seconds
    /// Uses Mozilla root certificates from `webpki-roots`
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(crate::DEFAULT_TIMEOUT_SECS))
    }

    /// Create a certificate fetcher with custom timeout
    pub fn with_timeout(timeout_duration: Duration) -> Self {
        // Set up root certificate store with Mozilla roots
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        // Configure TLS client
        // Note: We're intentionally permissive here because we're ANALYZING certificates,
        // not trusting them for production use
        let config = ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Self {
            timeout: timeout_duration,
            config: Arc::new(config),
        }
    }

    /// Fetch certificate chain from a TLS host
    ///
    /// # Arguments
    ///
    /// * `host` - Hostname or IP address
    /// * `port` - TCP port (typically 443 for HTTPS)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - DNS resolution fails
    /// - TCP connection fails
    /// - TLS handshake fails
    /// - Connection times out
    /// - No certificates returned
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tls_cert_analyzer::CertificateFetcher;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let fetcher = CertificateFetcher::new();
    /// let chain = fetcher.fetch("example.com", 443).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn fetch(&self, host: &str, port: u16) -> Result<Vec<Vec<u8>>> {
        // Validate input
        self.validate_hostname(host)?;
        
        // Build server address
        let addr = format!("{host}:{port}");

        // Attempt TCP connection with timeout
        let tcp_stream = timeout(self.timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| CertAnalyzerError::Timeout {
                host: host.to_string(),
                port,
                duration: self.timeout,
            })?
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    CertAnalyzerError::HostNotFound(host.to_string())
                } else {
                    CertAnalyzerError::Network(e)
                }
            })?;

        // TODO: Complete TLS handshake and extract certificates
        // For now, return placeholder
        // This will be implemented in the next phase with actual rustls integration
        
        tracing::info!("Connected to {addr}, extracting certificates...");
        
        // Placeholder: In real implementation, we'll:
        // 1. Create ServerName from host
        // 2. Create TlsConnector with our config
        // 3. Perform handshake
        // 4. Extract peer certificates from handshake
        
        Err(CertAnalyzerError::TlsHandshake(
            "TLS handshake not yet implemented - coming in next phase".to_string()
        ))
    }

    /// Validate hostname for security and correctness
    ///
    /// Checks:
    /// - No null bytes
    /// - Reasonable length (< 255 chars per RFC 1035)
    /// - Basic DNS name format or IP address
    fn validate_hostname(&self, host: &str) -> Result<()> {
        // Check for null bytes (security issue)
        if host.contains('\0') {
            return Err(CertAnalyzerError::InvalidInput(
                "Hostname contains null bytes".to_string(),
            ));
        }

        // Check length
        if host.is_empty() {
            return Err(CertAnalyzerError::InvalidInput(
                "Hostname is empty".to_string(),
            ));
        }

        if host.len() > 255 {
            return Err(CertAnalyzerError::InvalidInput(format!(
                "Hostname too long: {} characters (max 255)",
                host.len()
            )));
        }

        // TODO: Add more sophisticated DNS name validation
        // For now, basic checks are sufficient

        Ok(())
    }
}

impl Default for CertificateFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_hostname_valid() {
        let fetcher = CertificateFetcher::new();
        assert!(fetcher.validate_hostname("google.com").is_ok());
        assert!(fetcher.validate_hostname("example.com").is_ok());
        assert!(fetcher.validate_hostname("192.168.1.1").is_ok());
    }

    #[test]
    fn test_validate_hostname_invalid() {
        let fetcher = CertificateFetcher::new();
        
        // Null byte
        assert!(fetcher.validate_hostname("evil\0.com").is_err());
        
        // Empty
        assert!(fetcher.validate_hostname("").is_err());
        
        // Too long
        let long_host = "a".repeat(256);
        assert!(fetcher.validate_hostname(&long_host).is_err());
    }

    #[test]
    fn test_custom_timeout() {
        let fetcher = CertificateFetcher::with_timeout(Duration::from_secs(5));
        assert_eq!(fetcher.timeout, Duration::from_secs(5));
    }
}
