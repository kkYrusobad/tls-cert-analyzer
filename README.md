# TLS Certificate Analyzer

> **Graduate-level security tooling for X.509 certificate analysis and TLS auditing**

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org)

A comprehensive TLS certificate analyzer built to demonstrate graduate-level understanding of PKI infrastructure, cryptographic protocols, and security auditing. This tool fetches, parses, validates, and audits X.509 certificates from TLS services, detecting security issues and providing detailed analysis.

## 🎯 Project Objectives

This project is designed to demonstrate:

- **Cryptographic Protocol Understanding**: Deep knowledge of X.509, ASN.1, and PKI
- **Network Programming**: TLS handshake implementation and async I/O
- **Security Auditing**: Detection of weak cryptography, expiry issues, and misconfigurations
- **Research-Grade Implementation**: Based on RFCs and academic security research
- **Production-Quality Code**: Comprehensive error handling, testing, and documentation

## 🔬 Research Foundation

### Standards & RFCs

- **RFC 5280**: Internet X.509 Public Key Infrastructure Certificate and CRL Profile
- **RFC 6962**: Certificate Transparency
- **RFC 8446**: The Transport Layer Security (TLS) Protocol Version 1.3
- **RFC 8555**: Automatic Certificate Management Environment (ACME)

### Academic References

- **"SoK: SSL and HTTPS: Revisiting past challenges and evaluating certificate trust model enhancements"** (S&P 2013)
- **"Analysis of the HTTPS Certificate Ecosystem"** (IMC 2013)
- **"Measuring and Analyzing the Real-World Security of the TLS Ecosystem"** (Oakland 2017)

## ✨ Features

### Core Functionality

- ✅ **TLS Certificate Fetching**: Connect to hosts and retrieve full certificate chains using rustls
- ✅ **X.509 Parsing**: Complete ASN.1 and X.509 structure parsing with field extraction
- ✅ **Chain Validation**: Build and validate certificate chains against trust anchors
- ✅ **Expiry Detection**: Identify expired, not-yet-valid, or soon-to-expire certificates
- ✅ **Weak Crypto Detection**: Detect MD5, SHA-1 signatures, and weak RSA keys (<2048 bits)
- ✅ **SAN Validation**: Verify Subject Alternative Names and detect CN-only certificates
- ✅ **Multiple Output Formats**: JSON (machine-readable), table, and detailed text reports
- ✅ **Bulk Scanning**: Parallel scanning from host lists with configurable concurrency
- ✅ **Security Auditing**: Strict mode for CI/CD pipelines with exit codes
- ✅ **Certificate Export**: Export certificate chains in PEM format

### Advanced Features (Roadmap)

- 🔲 **OCSP Stapling**: Online Certificate Status Protocol validation
- 🔲 **CRL Checking**: Certificate Revocation List verification
- 🔲 **CT Log Integration**: Certificate Transparency log monitoring
- 🔲 **TLS Configuration Analysis**: Cipher suite and protocol version auditing
- 🔲 **Certificate Pinning**: Validate against expected certificates
- 🔲 **Custom Trust Stores**: Support for private CA certificates

## 🚀 Installation

### Prerequisites

- Rust 1.75 or later (2021 edition)
- No external dependencies required (pure Rust implementation)

### Build from Source

```bash
git clone https://github.com/kkyrusobad/tls-cert-analyzer.git
cd tls-cert-analyzer
cargo build --release
```

The binary will be available at `target/release/tls-cert-analyzer`.

### Quick Test

```bash
# Test the installation
./target/release/tls-cert-analyzer analyze google.com:443 --format text
```

## 📖 Usage

### Basic Certificate Analysis

```bash
# Analyze a single host
tls-cert-analyzer analyze google.com:443

# Specify custom port
tls-cert-analyzer analyze example.com:8443

# Output as JSON
tls-cert-analyzer analyze google.com:443 --format json

# Save to file
tls-cert-analyzer analyze google.com:443 --output report.json
```

### Bulk Scanning

Create a `hosts.txt` file with one host per line:
```
google.com:443
github.com:443
example.com:443
```

Then scan:
```bash
# Scan multiple hosts from file
tls-cert-analyzer scan --hosts hosts.txt --format table

# Parallel scanning with custom concurrency (default: 10)
tls-cert-analyzer scan --hosts hosts.txt --concurrency 20

# Save results to file
tls-cert-analyzer scan --hosts hosts.txt --output results.json --format json
```

### Security Auditing

```bash
# Check for security issues
tls-cert-analyzer audit google.com:443

# Strict mode (fail on any warning)
tls-cert-analyzer audit google.com:443 --strict

# Export security findings
tls-cert-analyzer audit google.com:443 --format json > findings.json
```

### Certificate Chain Export

```bash
# Export certificate chain in PEM format
tls-cert-analyzer export google.com:443 --output chain.pem

# Export specific certificate only
tls-cert-analyzer export google.com:443 --leaf-only
```

## 🏗️ Architecture

### Key Components

```
tls-cert-analyzer/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Library interface
│   ├── cli/                 # Command-line interface
│   │   ├── mod.rs
│   │   └── commands.rs
│   ├── cert/                # Certificate operations
│   │   ├── mod.rs
│   │   ├── fetcher.rs       # TLS connection and cert retrieval
│   │   ├── parser.rs        # X.509 parsing
│   │   └── validator.rs     # Chain validation
│   ├── analysis/            # Security analysis
│   │   ├── mod.rs
│   │   ├── expiry.rs        # Expiration checking
│   │   ├── crypto.rs        # Crypto strength analysis
│   │   └── san.rs           # SAN validation
│   ├── output/              # Output formatting
│   │   ├── mod.rs
│   │   ├── json.rs
│   │   ├── table.rs
│   │   └── text.rs
│   └── error.rs             # Error types
├── tests/                   # Integration tests
├── benches/                 # Performance benchmarks
└── examples/                # Usage examples
```

### Design Patterns

- **Builder Pattern**: Certificate analyzer configuration
- **Strategy Pattern**: Output formatters (JSON, table, text)
- **Repository Pattern**: Certificate storage and retrieval
- **Chain of Responsibility**: Validation pipeline

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run with logging
cargo test -- --nocapture

# Integration tests only
cargo test --test '*'

# Benchmarks
cargo bench
```

## 📊 Performance

The tool is optimized for:

- **Fast TLS Handshakes**: Reuses connections where possible
- **Parallel Scanning**: Concurrent host analysis
- **Memory Efficiency**: Streaming certificate parsing
- **Zero-Copy Parsing**: Where applicable with `x509-parser`

## 🔐 Security Considerations

### Threat Model

- **Trusted Network**: Assumes network path to target is trusted
- **No MITM Protection**: This is an analysis tool, not production TLS client
- **DoS Resistance**: Rate limiting for bulk scans

### Detected Vulnerabilities

| Issue | Severity | Description |
|-------|----------|-------------|
| Expired Certificate | CRITICAL | Certificate past validity period |
| Weak Signature (MD5) | CRITICAL | Cryptographically broken algorithm |
| Weak Signature (SHA-1) | HIGH | Deprecated, attack feasible |
| Short RSA Key (<2048) | HIGH | Insufficient key strength |
| Near Expiry (<30 days) | MEDIUM | Certificate expires soon |
| Self-Signed Certificate | INFO | Not trusted by default |
| Missing SAN | MEDIUM | Deprecated CN-only certificates |

## 📚 Educational Value

### Rust Concepts Demonstrated

- ✅ **Async/Await**: Tokio runtime for concurrent operations
- ✅ **Error Handling**: `thiserror` for custom error types, `anyhow` for applications
- ✅ **Traits**: Generic output formatters
- ✅ **Lifetimes**: Certificate data references
- ✅ **Type Safety**: Newtype pattern for certificate fields
- ✅ **Testing**: Unit, integration, and benchmark tests

### Cryptography Concepts

- ✅ **X.509 Structure**: Certificate fields, extensions, encoding
- ✅ **ASN.1**: Data structure encoding
- ✅ **PKI**: Certificate chains, trust anchors, validation
- ✅ **TLS Handshake**: ClientHello, ServerHello, certificate exchange

## 🛣️ Roadmap

### Phase 1: Core Functionality ✅ COMPLETED

- [x] TLS certificate fetching with tokio-rustls
- [x] Complete X.509 parsing with x509-parser
- [x] Expiry checking (expired, not-yet-valid, near-expiry)
- [x] Weak crypto detection (MD5, SHA-1, weak RSA)
- [x] Chain validation (issuer-subject matching, CA verification)
- [x] Multiple output formats (JSON, table, text)
- [x] CLI commands (analyze, scan, audit, export)
- [x] Bulk scanning with parallel execution
- [x] Security audit mode with strict checking
- [x] PEM certificate export

### Phase 2: Advanced Analysis (In Progress)

- [ ] OCSP validation
- [ ] CRL checking
- [ ] TLS version/cipher analysis
- [ ] Custom trust store support

### Phase 3: Integration & Research

- [ ] Certificate Transparency monitoring
- [ ] Integration with vulnerability databases
- [ ] ML-based anomaly detection in cert data
- [ ] Research paper on real-world TLS deployment

## 🤝 Contributing

This is an educational project, but contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure `cargo clippy` and `cargo fmt` pass
5. Submit a pull request

## 📄 License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## 🙏 Acknowledgments

- **rustls**: Modern TLS library
- **x509-parser**: Comprehensive X.509 parsing
- **RFC Authors**: Rigorous protocol specifications
- **Academic Researchers**: Security analysis methodologies

## 📧 Contact

For questions, suggestions, or collaboration:

- GitHub Issues: [Project Issues](https://github.com/kkyrusobad/tls-cert-analyzer/issues)
- Email: <prateek.yadav@edu.rptu.de>

---

**Built with ❤️**
