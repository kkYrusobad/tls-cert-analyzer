# Design Document: TLS Certificate Analyzer

## 1. Overview

### 1.1 Purpose

The TLS Certificate Analyzer is a security auditing tool designed to fetch, parse, validate, and analyze X.509 certificates from TLS-enabled services. It serves both as a practical security tool and as a demonstration of graduate-level understanding of PKI infrastructure and cryptographic protocols.

### 1.2 Goals

- **Educational**: Demonstrate deep understanding of X.509, ASN.1, and PKI concepts
- **Practical**: Provide actionable security insights for certificate auditing
- **Research**: Foundation for studies on real-world TLS deployment patterns
- **Production-Ready**: Robust error handling, testing, and performance optimization

### 1.3 Non-Goals

- **Full TLS Client**: Not a replacement for production TLS clients (use rustls/OpenSSL)
- **Certificate Authority**: No certificate signing or issuance functionality
- **Real-time Monitoring**: Designed for analysis, not continuous monitoring (initially)

## 2. Technical Architecture

### 2.1 System Components

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                            │
│  (Argument parsing, command routing, output formatting)      │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                    Certificate Fetcher                       │
│  - TLS connection establishment                              │
│  - Certificate chain retrieval                               │
│  - Connection pooling (for bulk scans)                       │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                    Certificate Parser                        │
│  - X.509 structure parsing (ASN.1)                           │
│  - Extension extraction                                      │
│  - Subject/Issuer parsing                                    │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                   Certificate Validator                      │
│  - Chain validation                                          │
│  - Trust anchor verification                                 │
│  - Signature verification                                    │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                    Security Analyzer                         │
│  - Expiry checking                                           │
│  - Weak crypto detection                                     │
│  - SAN validation                                            │
│  - Policy compliance                                         │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                    Output Formatter                          │
│  - JSON (machine-readable)                                   │
│  - Table (human-readable)                                    │
│  - Detailed text reports                                     │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow

```
User Input (host:port)
    │
    ▼
[Parse CLI Args] ──→ [Validate Input]
    │
    ▼
[TLS Connect] ──→ [Fetch Certificate Chain]
    │
    ▼
[Parse X.509] ──→ [Extract Fields & Extensions]
    │
    ▼
[Validate Chain] ──→ [Check Signatures & Trust]
    │
    ▼
[Analyze Security] ──→ [Check Expiry, Crypto, SANs]
    │
    ▼
[Format Output] ──→ [Display/Save Results]
```

## 3. Core Modules

### 3.1 Certificate Fetcher (`cert::fetcher`)

**Responsibilities:**

- Establish TLS connections to target hosts
- Retrieve server certificate chains
- Handle connection errors and timeouts
- Support connection pooling for bulk operations

**Key Design Decisions:**

1. **TLS Library Choice: `rustls`**
   - **Why**: Memory-safe, modern, no C dependencies
   - **Alternative**: `native-tls` (OpenSSL wrapper) - rejected for learning value
   - **Tradeoff**: `rustls` provides better understanding of TLS internals

2. **Async Runtime: `tokio`**
   - **Why**: Industry-standard, excellent for I/O-bound certificate fetching
   - **Alternative**: `async-std` - rejected for ecosystem maturity
   - **Tradeoff**: Requires understanding of async Rust, but enables high-performance bulk scanning

**Implementation Strategy:**

```rust
// Pseudo-code design
pub struct CertificateFetcher {
    connector: TlsConnector,
    timeout: Duration,
}

impl CertificateFetcher {
    pub async fn fetch(&self, host: &str, port: u16) -> Result<CertificateChain> {
        // 1. TCP connection
        // 2. TLS handshake
        // 3. Extract peer certificates
        // 4. Return chain
    }
}
```

### 3.2 Certificate Parser (`cert::parser`)

**Responsibilities:**

- Parse DER-encoded X.509 certificates
- Extract standard fields (subject, issuer, validity, public key)
- Parse extensions (SAN, key usage, basic constraints)
- Handle malformed certificates gracefully

**Key Design Decisions:**

1. **Parser Library: `x509-parser`**
   - **Why**: Pure Rust, well-maintained, comprehensive X.509 support
   - **Alternative**: `openssl` crate - rejected for same reasons as fetcher
   - **Tradeoff**: Must understand ASN.1 and DER encoding

2. **Error Handling Strategy: Fail-fast with context**
   - Invalid certificates return detailed errors
   - Malformed fields logged but don't crash the analyzer
   - Alternative: Silent failure - rejected for security tool requirements

**Data Structures:**

```rust
pub struct ParsedCertificate {
    pub subject: Name,
    pub issuer: Name,
    pub validity: ValidityPeriod,
    pub public_key: PublicKeyInfo,
    pub signature_algorithm: AlgorithmIdentifier,
    pub extensions: Extensions,
    pub raw_der: Vec<u8>,
}

pub struct Extensions {
    pub subject_alt_names: Option<Vec<String>>,
    pub key_usage: Option<KeyUsage>,
    pub extended_key_usage: Option<Vec<ExtendedKeyUsage>>,
    pub basic_constraints: Option<BasicConstraints>,
}
```

### 3.3 Certificate Validator (`cert::validator`)

**Responsibilities:**

- Verify certificate chains
- Check cryptographic signatures
- Validate against trust anchors
- Ensure proper CA hierarchy

**Key Design Decisions:**

1. **Trust Store: `webpki-roots`**
   - **Why**: Embedded Mozilla root certificates, no system dependency
   - **Alternative**: System trust store - may add later for flexibility
   - **Tradeoff**: Bundled roots may be outdated, but ensures consistency

2. **Validation Strategy: RFC 5280 Compliance**
   - Full path validation algorithm (Section 6)
   - Name constraints, policy constraints checking
   - Alternative: Basic chain validation - insufficient for graduate-level work

**Validation Pipeline:**

```
Certificate Chain
    │
    ▼
[Build Path] ──→ Find chain from leaf to root
    │
    ▼
[Verify Signatures] ──→ Check each signature against parent
    │
    ▼
[Check Validity] ──→ Ensure current time is within validity period
    │
    ▼
[Validate Names] ──→ Check name constraints
    │
    ▼
[Trust Anchor] ──→ Verify root is in trust store
    │
    ▼
VALID / INVALID
```

### 3.4 Security Analyzer (`analysis::*`)

**Responsibilities:**

- Detect security issues in certificates
- Classify findings by severity
- Provide remediation recommendations

**Analysis Modules:**

#### 3.4.1 Expiry Analyzer (`analysis::expiry`)

Checks:

- Certificate expired
- Certificate not yet valid
- Near expiry (configurable threshold, default 30 days)

Severity Levels:

- **CRITICAL**: Expired or not yet valid
- **MEDIUM**: Near expiry (30-90 days)
- **LOW**: Near expiry (90-180 days)

#### 3.4.2 Cryptography Analyzer (`analysis::crypto`)

Checks:

- **Signature Algorithm**:
  - MD5: CRITICAL (broken)
  - SHA-1: HIGH (deprecated, collision attacks)
  - SHA-256+: OK
- **Key Algorithm & Size**:
  - RSA < 2048 bits: HIGH
  - RSA 2048-4096 bits: OK
  - RSA > 4096 bits: INFO (unnecessary)
  - ECDSA P-256+: OK
  - DSA: HIGH (deprecated)
- **Public Key**:
  - Check for weak parameters
  - Detect known bad keys (if database available)

#### 3.4.3 SAN Analyzer (`analysis::san`)

Checks:

- SAN extension present (CN-only deprecated)
- SAN values match expected DNS names
- Wildcard certificate validation
- IP address SANs (if applicable)

### 3.5 Output Formatter (`output::*`)

**Responsibilities:**

- Format analysis results for different audiences
- Support multiple output formats
- Colorized terminal output for readability

**Output Formats:**

1. **JSON** (`output::json`):
   - Machine-readable
   - Full detail preservation
   - Schema versioning for stability

2. **Table** (`output::table`):
   - Human-readable summary
   - Uses `tabled` crate
   - Colorized severity levels

3. **Detailed Text** (`output::text`):
   - Full report with explanations
   - Remediation recommendations
   - Educational context for findings

## 4. Error Handling Strategy

### 4.1 Error Taxonomy

```rust
#[derive(Debug, thiserror::Error)]
pub enum CertAnalyzerError {
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
    
    #[error("TLS handshake failed: {0}")]
    TlsHandshake(String),
    
    #[error("Certificate parsing error: {0}")]
    ParseError(#[from] x509_parser::error::X509Error),
    
    #[error("Invalid certificate chain")]
    InvalidChain,
    
    #[error("Host not found: {0}")]
    HostNotFound(String),
    
    #[error("Timeout connecting to {0}")]
    Timeout(String),
}
```

### 4.2 Error Handling Principles

1. **Use `Result<T, E>` everywhere**: No panics in library code
2. **Context Propagation**: Use `anyhow` in binaries for rich context
3. **Typed Errors**: Use `thiserror` in libraries for specific error types
4. **Graceful Degradation**: Partial failures in bulk scans don't stop execution

## 5. Performance Considerations

### 5.1 Bottlenecks

1. **Network I/O**: TLS handshakes dominate runtime
2. **X.509 Parsing**: ASN.1 parsing can be CPU-intensive
3. **Bulk Scanning**: Serial scanning is slow

### 5.2 Optimizations

1. **Async Concurrency**:
   - Parallel TLS connections for bulk scans
   - Configurable concurrency limit (default: 10)
   - Prevents resource exhaustion

2. **Connection Pooling** (Future):
   - Reuse TCP connections for repeated scans
   - TLS session resumption

3. **Zero-Copy Parsing** (Where Possible):
   - Reference bytes from original DER
   - Avoid unnecessary allocations

4. **Caching** (Future):
   - Cache parsed certificates (keyed by fingerprint)
   - Cache validation results for chains

### 5.3 Benchmarks

Target performance (on modern hardware):

- Single certificate fetch + analysis: < 500ms
- Bulk scan (100 hosts): < 30s (with concurrency=10)
- X.509 parsing: < 10ms per certificate

## 6. Security Considerations

### 6.1 Threat Model

**Assumptions:**

- Tool runs on trusted machine
- Network path to target may be untrusted (we're analyzing, not trusting)
- Results are for informational purposes, not production decisions

**Out of Scope:**

- Protection against malicious target servers (this is analysis, not production use)
- MITM protection (we're often analyzing potentially compromised certificates)

**In Scope:**

- Input validation (prevent malformed hostnames from causing issues)
- Rate limiting (prevent accidental DoS of targets)
- Secure credential handling (if authentication added later)

### 6.2 Input Validation

```rust
// Hostname validation
fn validate_hostname(host: &str) -> Result<()> {
    // Check for valid DNS name or IP address
    // Reject null bytes, control characters
    // Limit length (RFC 1035: 255 characters)
}

// Port validation
fn validate_port(port: u16) -> Result<()> {
    // Ensure port is in valid range
    // Warn on non-standard TLS ports
}
```

### 6.3 Dependencies

- Regular `cargo audit` for known vulnerabilities
- Minimal dependency tree (avoid supply chain risk)
- Pin dependencies in `Cargo.lock`

## 7. Testing Strategy

### 7.1 Unit Tests

- Each module has `#[cfg(test)]` tests
- Test edge cases: expired certs, malformed ASN.1, weak crypto
- Mock network I/O for fast tests

### 7.2 Integration Tests

- Test with real certificates (embedded test certs)
- Test full analysis pipeline
- Test CLI interface with `assert_cmd`

### 7.3 Test Certificates

Create test certificates with different properties:

- Expired, valid, not-yet-valid
- Weak crypto (MD5, SHA-1, short RSA keys)
- Self-signed, chain, root CA
- Various extensions (SAN, EKU, etc.)

```bash
# Generate test certificates
openssl req -x509 -newkey rsa:1024 -keyout key.pem -out weak-rsa.pem -days 1
```

### 7.4 Benchmarks

```rust
// benches/cert_parsing.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_parse_certificate(c: &mut Criterion) {
    let cert_der = include_bytes!("../tests/data/cert.der");
    
    c.bench_function("parse_x509", |b| {
        b.iter(|| parse_certificate(black_box(cert_der)))
    });
}
```

## 8. Future Enhancements

### Phase 2: Advanced Analysis

1. **OCSP Validation**:
   - Check certificate revocation status
   - Implement OCSP stapling support
   - Reference: RFC 6960

2. **CRL Checking**:
   - Download and parse CRLs
   - Cache CRLs for performance
   - Reference: RFC 5280 Section 6.3

3. **CT Log Monitoring**:
   - Query Certificate Transparency logs
   - Detect unauthorized certificates
   - Reference: RFC 6962

### Phase 3: ML Integration

1. **Anomaly Detection**:
   - Embedding of certificate features
   - Clustering of certificate patterns
   - Detection of unusual certificates

2. **Threat Intelligence**:
   - Integration with threat feeds
   - Correlation with known malicious certs
   - Phishing detection via certificate analysis

### Phase 4: Research

1. **Large-Scale Studies**:
   - Scan Alexa Top 1M for TLS deployment analysis
   - Publication-quality research on certificate ecosystem
   - Trend analysis over time

## 9. References

### RFCs

- **RFC 5280**: X.509 PKI Certificate and CRL Profile
- **RFC 6125**: Domain-Based Name Validation
- **RFC 6960**: OCSP
- **RFC 6962**: Certificate Transparency
- **RFC 8446**: TLS 1.3

### Academic Papers

1. Durumeric et al., "Analysis of the HTTPS Certificate Ecosystem," IMC 2013
2. Amann et al., "Mission Accomplished? HTTPS Security after DigiNotar," IMC 2017
3. Chung et al., "Measuring and Analyzing the Real-World Security of the TLS Ecosystem," Oakland 2017

### Tools & Inspirations

- **testssl.sh**: Comprehensive TLS testing
- **sslscan**: SSL/TLS scanner
- **SSLyze**: Python TLS analyzer (inspiration for architecture)

---

**Document Version**: 1.0  
**Last Updated**: 2026-01-18  
**Author**: Graduate-level Computer Science Project
