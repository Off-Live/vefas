# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VEFAS (Verifiable Execution Framework for Agents) is a revolutionary zkTLS client that uses a host-rustls + guest-verifier architecture for optimal proof efficiency. It enables AI agents to make cryptographically verifiable external requests, eliminating hallucinations about external actions.

## Architecture

VEFAS uses a unique **host-guest separation** architecture:
- **Host (std)**: Uses full rustls + aws-lc-rs for real TLS connections and captures session data
- **Guest (no_std + alloc)**: Runs minimal TLS verifier (~1000 lines) in zkVM using SP1/RISC0 precompiles
- **Canonical Bundle**: Deterministic format extracted from rustls session data for guest verification

## Commands

### Essential Build & Test Commands
```bash
# Run all tests (primary development command)
cargo test --workspace --verbose

# Test specific platforms
cargo test --package vefas-sp1
cargo test --package vefas-risc0

# Test specific crates
cargo test --package vefas-core
cargo test --package vefas-gateway
cargo test --package vefas-crypto

# Code quality
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo audit

# Build workspace
cargo build --workspace
cargo build --workspace --release

# Documentation
cargo doc --workspace --no-deps --open
```

### RFC 8448 Vector Tests (Optional)
These tests require environment variables:
```bash
# Test single vector file
RFC8448_VECTOR_FILE=/path/to/vector.json cargo test -p vefas-crypto --tests

# Test all vectors in directory
RFC8448_VECTORS_DIR=/path/to/vectors cargo test -p vefas-crypto --tests
```

## Crate Structure

The project uses a revolutionary architecture with clear separation of concerns:

```
VEFAS Workspace
├── crates/
│   ├── vefas-types/             # Shared no_std types (bundle, errors, http, tls)
│   ├── vefas-crypto/            # Crypto traits and error types (no_std)
│   ├── vefas-crypto-native/     # Pure-Rust crypto provider (dev/CI)
│   ├── vefas-crypto-sp1/        # SP1 crypto provider bindings with precompiles
│   ├── vefas-crypto-risc0/      # RISC0 crypto provider bindings with precompiles
│   ├── vefas-rustls/            # rustls CryptoProvider with ephemeral key capture
│   ├── vefas-core/              # Host TLS+HTTP client; builds VefasCanonicalBundle
│   ├── vefas-gateway/           # REST API server: /requests, /verify, /health
│   ├── vefas-sp1/               # SP1 integration (guest program + host script)
│   └── vefas-risc0/             # RISC0 integration (methods, guest, host)
│
└── tests/                       # Root integration tests (spawn gateway, e2e)
```

## Key Implementation Details

### Data Flow
1. **vefas-core**: Unified client using rustls + aws-lc-rs creates VefasCanonicalBundle
2. **vefas-gateway**: REST API that orchestrates proof generation via SP1/RISC0
3. **Guest programs**: Minimal TLS verifiers that process canonical bundles and generate proofs

### Crypto Provider Strategy
- **Host**: Uses rustls + aws-lc-rs (no custom crypto providers)
- **Guest**: Platform-specific providers (`vefas-crypto-sp1`, `vefas-crypto-risc0`) with direct precompiles
- **Testing**: Pure Rust provider (`vefas-crypto-native`) for CI/dev

### TLS Protocol Support
- **TLS 1.3 only** (RFC 8446)
- **Cipher suites**: TLS_AES_128_GCM_SHA256 with platform optimization
- **Key exchange**: ECDHE with X25519 or P-256
- **Authentication**: ECDSA, Ed25519, RSA certificate signatures

## Development Principles

### TDD Requirements (from .cursor/rules/)
- **Strict Red → Green → Refactor workflow**
- Write failing tests first, implement minimal code to pass, then refactor
- No production code without corresponding tests
- Test directory structure: `fixtures/`, `unit/`, `integration/`, `guest/`, `performance/`

### TLS Knowledge Sources
Always reference these authoritative sources:
- **RFC 8446 (TLS 1.3)**: https://datatracker.ietf.org/doc/html/rfc8446
- **RFC 8448 (TLS 1.3 Test Vectors)**: https://datatracker.ietf.org/doc/html/rfc8448
- **TLS1.3 Explained**: https://tls13.xargs.org/#open-all
- **rustls Documentation**: https://docs.rs/rustls/latest/rustls/

### Platform Documentation
- **SP1 Precompiles**: https://docs.succinct.xyz/docs/sp1/optimizing-programs/precompiles
- **RISC0 Precompiles**: https://dev.risczero.com/api/zkvm/precompiles

## API Endpoints (Gateway)

The `vefas-gateway` provides these REST endpoints:

- `POST /api/v1/requests` - Execute HTTPS request and generate proof
- `POST /api/v1/verify` - Verify a proof and return verified claim
- `GET /api/v1/health` - Service health and available platforms
- `GET /` - Service info

## Test Organization

### RFC 8448 Vector Tests
Optional tests using environment variables:
- `RFC8448_VECTOR_FILE=/path/to/vector.json` - Single vector validation
- `RFC8448_VECTORS_DIR=/path/to/dir` - All vectors in directory

### Integration Tests
- Located in `tests/integration_tests.rs`
- Spawns gateway server for end-to-end testing
- Tests real HTTPS requests with proof generation

## Performance Characteristics

**Key Innovation**: 10-100x cheaper proofs through minimal guest verifier + direct precompile usage:
- **Host**: Full rustls + aws-lc-rs for real TLS connections
- **Guest**: Minimal verifier (~1000 lines) + SP1/RISC0 precompiles
- **No custom crypto on host**: Eliminates abstractions, uses proven rustls stack

## Quality Standards

- Zero `unsafe` code unless mandatory
- Idiomatic `Result<T, E>` error handling
- Comprehensive error messages and logging
- Memory efficient for zkVM constraints
- Production-grade security practices (no exposed secrets/keys)