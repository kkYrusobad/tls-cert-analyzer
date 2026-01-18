# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial project structure
- Basic certificate fetching capability
- X.509 certificate parsing
- Expiry date checking
- Weak cryptography detection (MD5, SHA-1, short RSA keys)
- SAN (Subject Alternative Name) validation
- Multiple output formats (JSON, table, text)
- Comprehensive test suite
- CLI with `clap`
- Graduate-level documentation (README, DESIGN)

### Changed

- N/A (initial release)

### Deprecated

- N/A

### Removed

- N/A

### Fixed

- N/A

### Security

- Input validation for hostnames and ports
- Rate limiting for bulk scans

## [0.1.0] - YYYY-MM-DD (Not yet released)

### Added

- Initial release
- Core certificate analysis functionality
- Security auditing capabilities
- Educational documentation

---

[Unreleased]: https://github.com/kkyrusobad/tls-cert-analyzer/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kkyrusobad/tls-cert-analyzer/releases/tag/v0.1.0
