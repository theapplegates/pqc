# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Sequoia PGP is a complete implementation of OpenPGP (RFC 9580 and RFC 4880) written in Rust. The project consists of multiple crates in a Cargo workspace, with the core `sequoia-openpgp` crate providing low-level OpenPGP functionality, and additional mid-level crates for specific features.

## Workspace Structure

This is a Cargo workspace with the following main crates:

- **openpgp/**: Core OpenPGP implementation (`sequoia-openpgp`). This is the primary crate and contains most of the functionality.
- **net/**: Network services for OpenPGP (`sequoia-net`)
- **ipc/**: Low-level IPC services for Sequoia and GnuPG (`sequoia-ipc`)
- **autocrypt/**: Low-level Autocrypt support (`sequoia-autocrypt`)
- **buffered-reader/**: Custom buffered reader implementation

## Common Development Commands

### Building

```bash
# Build all workspace members
cargo build --all

# Build with release optimizations
cargo build --release --all

# Build a specific package
cargo build -p sequoia-openpgp

# Build with different crypto backend (disable default first)
cargo build --no-default-features --features crypto-cng,compression
```

### Testing

```bash
# Run all tests in the workspace
cargo test --all

# Run tests for a specific package
cargo test -p sequoia-openpgp

# Run a specific test
cargo test -p sequoia-openpgp <test_name>

# Skip leak tests (as done in CI)
cargo test --all -- --skip leak_tests
```

### Code Quality

```bash
# Check code without building
cargo check --all

# Run Clippy linter
cargo clippy --all

# Check for fuzzing compatibility
cargo check --manifest-path openpgp/Cargo.toml --no-default-features \
  --features crypto-fuzzing,compression,allow-experimental-crypto,allow-variable-time-crypto
```

### Documentation

```bash
# Build documentation (including private items)
cargo doc --document-private-items --no-deps

# Build and open docs
cargo doc --open
```

### Running Examples

```bash
# List available examples
ls openpgp/examples/

# Run an example
cargo run --example <example_name> -p sequoia-openpgp

# Example: Run the generate-sign-verify demo
cargo run --example generate-sign-verify -p sequoia-openpgp
```

## Architecture

### Core Components (openpgp/src/)

- **crypto/**: Cryptographic operations with pluggable backend system
  - **backend/**: Multiple crypto backend implementations (Nettle, OpenSSL, Botan, CNG, RustCrypto, fuzzing)
  - **types/**: Cryptographic algorithm enums (hash, symmetric, AEAD, curves)
  - Backend is selected at compile-time via Cargo features
- **packet/**: OpenPGP packet types and parsing
  - Individual packet types (signature, key, literal, compressed_data, etc.)
  - Packet header parsing (CTB and length encoding)
- **cert/**: Certificate (key) handling
  - **amalgamation/**: Component iteration and access
  - **builder/**: Certificate generation
  - **parser/**: Certificate parsing with low-level grammar support
- **parse/**: Stream-based message parsing
- **serialize/**: Message serialization
  - **stream/**: Streaming encryption/signing API
- **armor/**: ASCII armor encoding/decoding with CRC24
- **policy/**: Cryptographic policy enforcement
- **types/**: Common OpenPGP types (signatures, keys, etc.)

### Crypto Backend System

The crate supports multiple cryptographic backends selected at compile-time via Cargo features. **Exactly one backend must be selected** (features are not additive for backends):

- `crypto-nettle` (default): Uses Nettle library (requires version 3.9.1+)
- `crypto-openssl`: Uses OpenSSL
- `crypto-botan` or `crypto-botan2`: Uses Botan v3 or v2
- `crypto-cng`: Windows CNG (Windows 10+)
- `crypto-rust`: RustCrypto crates (experimental, requires `allow-experimental-crypto` and `allow-variable-time-crypto`)
- `crypto-fuzzing`: Fuzzing backend (no real crypto)

When working with crypto backends:
- Backend selection happens in `openpgp/src/crypto/backend/mod.rs`
- Each backend implements traits defined in `backend/interface.rs`
- Most crypto operations are abstracted through the backend interface

### Feature Flags

Important feature combinations:

- **Compression**: `compression` (enables both deflate and bzip2), `compression-deflate`, `compression-bzip2`
- **Crypto backends**: Must use `default-features = false` and select exactly one backend
- **Experimental/variable-time opt-ins**: `allow-experimental-crypto`, `allow-variable-time-crypto`

Leaf crates should expose backend selection to downstream users. Intermediate crates must disable default features and only enable backends for tests/docs.

## Code Conventions

### Rust Version

- MSRV: 1.85 (specified in `openpgp/Cargo.toml`)
- Target: Version available in Debian testing
- When updating MSRV, update `Cargo.toml`, `clippy.toml`, README files, and CI configs

### Clippy Configuration

Custom thresholds in `clippy.toml`:
- `enum-variant-size-threshold = 512`
- `too-many-arguments-threshold = 10`
- `type-complexity-threshold = 500`

### Performance Optimizations

- Crypto crates (AES, RSA, ed25519, etc.) are compiled with `opt-level = 2` even in debug builds for acceptable performance
- Custom `vec_truncate()` and `vec_resize()` helpers avoid slow drop implementations in debug builds

### Security Considerations

- Sensitive data should use `memsec` for secure memory handling
- Secret key material uses zeroization features from crypto crates
- SHA-1 collision detection is enabled via `sha1collisiondetection` crate

## Testing

- Unit tests are alongside source files
- Integration tests in `openpgp/tests/`
- Test data in `openpgp/tests/data/`
- Examples serve as both documentation and integration tests
- Leak tests can be skipped with `-- --skip leak_tests`

## Branch Information

- Main branch: `main`
- Current branch: `pqc` (post-quantum cryptography work)
- The project uses GitLab CI for continuous integration

## Important Files

- `openpgp-policy.toml`: Cryptographic policy configuration
- `Cargo.lock`: Should remain unchanged after builds (CI checks this)
- `.gitlab-ci.yml`: CI configuration with custom pipeline component
