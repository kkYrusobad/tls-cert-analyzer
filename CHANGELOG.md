# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-03

### Added
- **Complete TLS certificate fetching** using tokio-rustls
  - Full TLS handshake implementation
  - Server Name Indication (SNI) support
  - Certificate chain extraction from live servers
  - Connection timeout handling

- **X.509 certificate parsing** using x509-parser
  - Subject and issuer extraction
  - Validity period parsing
  - Public key information (algorithm, key size)
  - Signature algorithm detection
  - Subject Alternative Names (SANs) parsing
  - CA certificate detection via Basic Constraints
  - SHA-256 fingerprint calculation
  - Serial number extraction

- **Certificate chain validation**
  - Issuer-subject chain verification
  - Validity period checking
  - CA hierarchy validation
  - Leaf certificate verification

- **Security analysis modules**
  - Expiry analyzer: Detects expired, not-yet-valid, and near-expiry certificates
  - Crypto analyzer: Identifies MD5 signatures, SHA-1 signatures, weak RSA keys
  - SAN analyzer: Detects missing Subject Alternative Names

- **CLI commands**
  - `analyze`: Single host certificate analysis with detailed output
  - `scan`: Bulk scanning from host list with parallel execution
  - `audit`: Security audit mode with strict checking and exit codes
  - `export`: Certificate chain export in PEM format

- **Output formatters**
  - JSON: Machine-readable output with full details
  - Table: Human-readable tabular format
  - Text: Detailed text reports with remediation recommendations

- **Additional features**
  - Risk score calculation (0-100)
  - Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
  - Colorized terminal output
  - Progress bars for bulk scanning
  - Verbose logging mode
  - File output support

### Technical Details
- Pure Rust implementation with no C dependencies
- Async runtime: tokio
- TLS library: rustls 0.23 + tokio-rustls 0.26
- X.509 parsing: x509-parser 0.16
- Trust store: webpki-roots 0.26 (Mozilla root certificates)
- Error handling: thiserror + anyhow
- CLI framework: clap 4.4 with derive macros

### Known Limitations
- OCSP validation not yet implemented
- CRL checking not yet implemented
- Certificate Transparency log verification not implemented
- Custom trust stores not supported
- TLS protocol/cipher analysis not included

[0.1.0]: https://github.com/kkyrusobad/tls-cert-analyzer/releases/tag/v0.1.0
