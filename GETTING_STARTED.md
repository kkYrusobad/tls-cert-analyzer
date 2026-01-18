# Getting Started Guide

Welcome to the TLS Certificate Analyzer project! This guide will help you understand the project structure and get started with development.

## 🎯 Project Status

**Phase**: Foundation Complete ✅  
**Next Phase**: Core Implementation (TLS fetching + X.509 parsing)

### ✅ What's Implemented

- **Project Structure**: Complete module organization
- **Error Handling**: Comprehensive typed errors with `thiserror`
- **Analysis Framework**:
  - Expiry analyzer (checks for expired/expiring certificates)
  - Crypto analyzer (detects weak signatures and keys)
  - SAN analyzer (validates Subject Alternative Names)
- **Output Formatters**: JSON, table, and text formats
- **CLI Interface**: Full command structure with `clap`
- **Documentation**: README, DESIGN.md, inline docs
- **Testing**: Unit tests for all modules
- **CI/CD**: GitHub Actions workflow
- **Build System**: Compiles successfully with all dependencies

### 🚧 What's Next (for you to implement!)

- **TLS Connection**: Complete `CertificateFetcher::fetch()` with actual rustls handshake
- **X.509 Parsing**: Implement `parse_certificate()` using x509-parser
- **Chain Validation**: Implement RFC 5280 path validation
- **Integration Tests**: Add tests with real certificates
- **Examples**: Complete working examples

## 🏗️ Architecture Overview

```
tls-cert-analyzer/
├── src/
│   ├── error.rs              # Error types (COMPLETE)
│   ├── lib.rs                # Library interface (COMPLETE)
│   ├── main.rs               # CLI entry point (COMPLETE)
│   ├── cert/
│   │   ├── fetcher.rs        # TLS fetching (TODO: complete handshake)
│   │   ├── parser.rs         # X.509 parsing (TODO: implement)
│   │   └── validator.rs      # Chain validation (TODO: implement)
│   ├── analysis/
│   │   ├── expiry.rs         # Expiry checks (COMPLETE)
│   │   ├── crypto.rs         # Crypto checks (COMPLETE)
│   │   └── san.rs            # SAN checks (COMPLETE)
│   └── output/
│       └── mod.rs            # Output formatting (COMPLETE)
├── tests/                    # Integration tests (TODO: add)
├── benches/                  # Benchmarks (placeholder)
└── examples/                 # Usage examples (placeholder)
```

## 🚀 Quick Start

### 1. Build the Project

```bash
cd /home/kky/Documents/Projects/tls-cert-analyzer
cargo build
```

### 2. Run Tests

```bash
cargo test
```

Expected output: All unit tests pass ✅

### 3. Try the CLI

```bash
cargo run -- analyze google.com:443 --format text
```

You'll see a message that core implementation is coming – that's expected!

### 4. Check Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy

# Run security audit
cargo audit
```

## 📚 Learning Path

Follow this path to implement the remaining features while learning Rust deeply:

### Step 1: Understand the Current Code (Week 1)

1. **Read the documentation**:
   - Start with `README.md` for project overview
   - Read `DESIGN.md` for architecture decisions
   - Review inline documentation in each module

2. **Study the error handling**:
   - `src/error.rs` - See how `thiserror` works
   - Notice the custom `Result` type alias
   - Understand error propagation with `?` operator

3. **Examine the analysis modules**:
   - `src/analysis/expiry.rs` - Simple, clear logic
   - See how `Finding` and `Severity` work
   - Understand the risk scoring algorithm

### Step 2: Implement TLS Fetching (Week 2)

**File**: `src/cert/fetcher.rs`

**Task**: Complete the `fetch()` method

**What you need to learn**:

- Rustls `ClientConnection` API
- Async Rust with Tokio
- ServerName validation
- Certificate extraction from TLS connection

**Hints**:

```rust
// You'll need to:
1. Create a ServerName from the host
2. Create a ClientConnection with the config
3. Wrap TCP stream in TLS stream
4. Perform handshake
5. Extract peer_certificates()
6. Convert to Vec<Vec<u8>>
```

**Resources**:

- [Rustls documentation](https://docs.rs/rustls/)
- [Tokio tutorial](https://tokio.rs/tokio/tutorial)
- Look at rustls examples in their repo

### Step 3: Implement X.509 Parsing (Week 3)

**File**: `src/cert/parser.rs`

**Task**: Complete `parse_certificate()`

**What you need to learn**:

- ASN.1 DER encoding
- X.509 certificate structure
- Using `x509-parser` crate
- SHA-256 fingerprint calculation

**Hints**:

```rust
// You'll need to:
1. Call x509_parser::parse_x509_certificate()
2. Extract subject, issuer, validity
3. Parse extensions (especially SANs)
4. Calculate SHA-256 fingerprint (use sha2 crate)
5. Map to ParsedCertificate struct
```

**Resources**:

- [x509-parser docs](https://docs.rs/x509-parser/)
- RFC 5280 (X.509 spec)
- [ASN.1 primer](https://www.oss.com/asn1/resources/asn1-made-simple/introduction.html)

### Step 4: Implement Chain Validation (Week 4)

**File**: `src/cert/validator.rs`

**Task**: Implement RFC 5280 path validation

**This is advanced!** Start simple:

1. Verify each certificate signature against its parent
2. Check validity periods
3. Verify chain leads to trusted root

**Resources**:

- RFC 5280 Section 6
- Look at how webpki does validation
- Consider using rustls's verification initially

### Step 5: Integration Testing (Week 5)

**Create**: `tests/integration_test.rs`

**Task**: Test with real certificates

```bash
# Generate test certificates
mkdir tests/data
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout tests/data/key.pem \
  -out tests/data/cert.pem \
  -days 365 -subj "/CN=test.example.com"
```

Test scenarios:

- Valid certificate
- Expired certificate
- Weak crypto (RSA 1024)
- Missing SAN

## 🔬 Understanding Key Concepts

### Why Rustls instead of OpenSSL?

1. **Memory Safety**: Pure Rust, no C vulnerabilities
2. **Learning**: Understand TLS without FFI complexity
3. **Modern**: TLS 1.2+ only, cleaner API

### Why x509-parser?

1. **Pure Rust**: No C dependencies
2. **Well-documented**: Good examples
3. **Complete**: Handles all X.509 extensions

### Error Handling Philosophy

We use `thiserror` in the library for:

- Type-safe errors
- Pattern matching on error variants
- Clear error messages

We use `anyhow` in binaries for:

- Easy context addition
- Rich error traces
- Quick prototyping

### Analysis Architecture

The analyzer uses the **Strategy Pattern**:

- Each analyzer (expiry, crypto, SAN) is independent
- All return `Vec<Finding>`
- CertificateAnalyzer coordinates them
- Easy to add new analyzers!

## 🎓 Graduate-Level Considerations

As you implement, think about:

1. **Security**:
   - Constant-time comparisons where needed?
   - Input validation (we started this)
   - Side-channel resistance

2. **Performance**:
   - Zero-copy where possible
   - Async for I/O
   - Parallel processing for bulk scans

3. **Research**:
   - Can you detect novel attack patterns?
   - What metrics could you collect?
   - Publication potential?

## 🐛 Debugging Tips

### Enable detailed logging

```bash
RUST_LOG=debug cargo run -- analyze google.com:443
```

### Use rust-gdb for debugging

```bash
cargo build
rust-gdb target/debug/tls-cert-analyzer
```

### Print types

```rust
let x = some_complex_expression();
let _: () = x;  // Compiler will show the type!
```

## 📖 Recommended Reading Order

1. **The Rust Book** - Chapters 10 (Generics, Traits, Lifetimes), 16 (Concurrency)
2. **Async Rust Book** - Especially async/await fundamentals
3. **RFC 5280** - Sections 4 (Certificate), 6 (Validation)
4. **RFC 8446** - TLS 1.3 spec (skim to understand handshake)

## ✅ Next Session Checklist

When you come back to this project:

- [ ] Run `cargo test` - should all pass
- [ ] Read one module completely  
- [ ] Pick a TODO to implement
- [ ] Write tests first (TDD)
- [ ] Implement feature
- [ ] Run `cargo clippy`
- [ ] Document what you learned

## 🤝 Getting Help

**Stuck?** This is a learning project!

1. Read the compiler errors carefully
2. Check the crate documentation
3. Look at the DESIGN.md for context
4. Try smaller examples first

**Key Insight**: Every "TODO" is intentional – it's where YOUR learning happens!

## 🎯 Success Criteria

You'll know you've succeeded when:

1. ✅ `cargo run -- analyze google.com:443` returns real analysis
2. ✅ All tests pass
3. ✅ You can explain every line of code
4. ✅ You understand X.509 structure
5. ✅ You can extend it with new analyzers

---

**Remember**: This is a **learning journey**. Take your time, understand each concept deeply, and don't just copy-paste solutions. The goal is mastery, not speed.

**You've got this!** 🚀
