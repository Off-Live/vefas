# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VEFAS (Verifiable Execution Framework for Agents) is a zkTLS client that generates cryptographic proofs of HTTPS requests and responses. It enables AI agents to prove they performed external actions (e.g., "Email sent") without relying on trust, MPC, or notaries.

**Key Innovation**: Two-phase architecture:
1. **Phase 1 (Host)**: Establish real TLS 1.3 connection, capture handshake and HTTP exchange
2. **Phase 2 (zkVM)**: Verify TLS handshake, validate certificates, generate zero-knowledge proof

**Supported Platforms**: RISC0 and SP1 zkVMs

## Build Commands

### Basic Build
```bash
# Build entire workspace
cargo build --workspace

# Build with release optimizations (recommended for proof generation)
cargo build --workspace --release
```

### Testing
```bash
# Run all tests in workspace
cargo test --workspace

# Run tests for specific crate
cargo test -p vefas-core
cargo test -p vefas-gateway
cargo test -p vefas-crypto

# Run specific test
cargo test --test e2e_tests
```

### zkVM Guest Programs

**SP1 Guest Program:**
```bash
# Build SP1 guest program
cd crates/vefas-sp1/program
cargo prove build

# Or from root
cargo build -p vefas-sp1-program --release
```

**RISC0 Guest Program:**
```bash
# Build RISC0 guest program
cd crates/vefas-risc0/methods/guest
cargo build --release --target riscv32im-unknown-none-elf

# Or from root
cargo build -p vefas-risc0-methods
```

### Linting and Formatting
```bash
# Check formatting
cargo fmt -- --check

# Auto-format code
cargo fmt

# Run clippy
cargo clippy --workspace -- -D warnings
```

### Running the Gateway
```bash
# Start the REST API server (port 3000)
cargo run --package vefas-gateway --release

# Test with curl
curl -X POST http://127.0.0.1:3000/api/v1/requests \
  -H "Content-Type: application/json" \
  -d '{"method": "GET", "url": "https://example.com", "proof_platform": "risc0"}'
```

## Architecture

### Crate Organization

**Core Infrastructure:**
- `vefas-types`: Platform-agnostic no_std types for zkTLS verification (canonical bundles, proof claims)
- `vefas-core`: Production HTTP client with TLS capture (`VefasClient`)
- `vefas-gateway`: REST API server (Axum-based) for proof generation and verification
- `vefas-rustls`: Custom rustls crypto provider with TLS message capture capabilities

**Cryptographic Layer:**
- `vefas-crypto`: Trait-only crate with platform-agnostic interfaces (Hash, AEAD, KDF, Signature)
- `vefas-crypto-native`: Native implementations using aws-lc-rs (host environment)
- `vefas-crypto-sp1`: SP1 zkVM implementations using SP1 precompiles
- `vefas-crypto-risc0`: RISC0 zkVM implementations using RISC0 precompiles

**zkVM Integration:**
- `vefas-sp1/`: SP1 prover (host) + guest program
  - `src/lib.rs`: `VefasSp1Prover` - proof generation/verification
  - `program/src/main.rs`: Guest program executed in SP1 zkVM
  - `script/`: Build script for compiling guest program
- `vefas-risc0/`: RISC0 prover (host) + guest program
  - `src/lib.rs`: `VefasRisc0Prover` - proof generation/verification
  - `methods/guest/src/main.rs`: Guest program executed in RISC0 zkVM

### Key Data Flow

```text
HTTP Request → VefasClient → TLS Handshake Capture → VefasCanonicalBundle
                                                              ↓
                                                    zkVM Guest Program
                                                    (SP1 or RISC0)
                                                              ↓
                                                    Cryptographic Verification
                                                              ↓
                                                    VefasProofClaim
```

**VefasCanonicalBundle** (vefas-types/src/bundle.rs):
- Contains complete TLS session data: ClientHello, ServerHello, Certificate chain, encrypted request/response
- Includes ephemeral private key (captured during handshake for debug/verification)
- Domain, timestamp, and verifier nonce for binding
- Sent from host to zkVM guest program

**VefasProofClaim** (vefas-types/src/output.rs):
- Contains verified cryptographic commitments
- HTTP request/response data (selective disclosure supported)
- Execution metadata (cycles, memory, platform)
- Returned from zkVM to host after verification

### std vs no_std Architecture

The codebase supports both standard (host) and no_std (guest zkVM) environments:

**std crates (host environment):**
- `vefas-core`: TLS client, HTTP processing, bundle building
- `vefas-gateway`: REST API server
- `vefas-rustls`: Custom rustls provider with capture
- `vefas-crypto-native`: Native crypto implementations
- `vefas-sp1/src/lib.rs`: SP1 prover (host)
- `vefas-risc0/src/lib.rs`: RISC0 prover (host)

**no_std crates (guest environment):**
- `vefas-types`: All core types (use `#![no_std]`)
- `vefas-crypto`: Trait-only interfaces (use `#![no_std]`)
- `vefas-crypto-sp1`: SP1 precompile implementations
- `vefas-crypto-risc0`: RISC0 precompile implementations
- `vefas-sp1/program`: SP1 guest program (use `#![no_std]`)
- `vefas-risc0/methods/guest`: RISC0 guest program (use `#![no_std]`)

### Merkle-Based Selective Disclosure

Both zkVM guest programs use Merkle proofs for efficient verification:

**Why Merkle Proofs:**
- Dramatically reduces circuit size (90%+ reduction vs. full TLS parsing)
- Enables selective disclosure (prove individual fields independently)
- Faster proof generation

**What's Verified:**
1. Merkle tree integrity for TLS components
2. ServerFinished message (HKDF + HMAC verification)
3. HTTP request/response integrity
4. Domain binding

**Implementation:**
- `vefas-crypto/src/merkle.rs`: Core Merkle verification logic
- `vefas-sp1/program/src/selective_extraction.rs`: SP1 selective disclosure
- `vefas-risc0/methods/guest/src/selective_extraction.rs`: RISC0 selective disclosure

## Development Guidelines

### Adding New Cryptographic Primitives

1. Define trait in `vefas-crypto/src/traits.rs`
2. Implement for native in `vefas-crypto-native/src/crypto_provider.rs`
3. Implement for SP1 in `vefas-crypto-sp1/src/crypto_provider.rs` (using SP1 precompiles)
4. Implement for RISC0 in `vefas-crypto-risc0/src/crypto_provider.rs` (using RISC0 precompiles)

Example pattern:
```rust
// vefas-crypto/src/traits.rs
pub trait NewCryptoOp {
    fn perform(&self, input: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

// vefas-crypto-native/src/crypto_provider.rs
impl NewCryptoOp for NativeCryptoProvider {
    fn perform(&self, input: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Use aws-lc-rs
    }
}

// vefas-crypto-sp1/src/crypto_provider.rs
impl NewCryptoOp for SP1CryptoProvider {
    fn perform(&self, input: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Use sp1_zkvm::precompiles
    }
}
```

### Testing Strategy

**Unit Tests**: Each crate has `#[cfg(test)]` modules
- Test individual functions in isolation
- Use `rstest` for parameterized tests

**Integration Tests**: `tests/e2e_tests.rs`
- Test full proof generation and verification flow
- Test both SP1 and RISC0 platforms

**Cross-Platform Consistency**: `vefas-crypto/tests/cross_platform_consistency.rs`
- Verify all crypto providers produce identical results
- Critical for ensuring zkVM proofs match host expectations

### Performance Considerations

**RISC0 Proof Generation:**
- CPU: 10-60 seconds
- GPU (CUDA): 1-5 seconds (10-100x faster)
- Enable with `--features cuda`

**SP1 Proof Generation:**
- Uses SP1 precompiles for optimized crypto operations
- Faster than RISC0 for crypto-heavy workloads

**Bundle Compression:**
- LZSS compression for large bundles (>10KB)
- Reduces zkVM memory usage and cycles
- See `vefas-types/src/compression.rs`

### Common Patterns

**Error Handling:**
- Use `VefasResult<T>` (alias for `Result<T, VefasError>`)
- Errors defined in `vefas-types/src/errors.rs`
- Include context: `VefasError::crypto_error(CryptoErrorType::InvalidKey, "context")`

**Serialization:**
- Use `bincode` for deterministic serialization (zkVM compatible)
- All types implement `Serialize` + `Deserialize`

**Feature Flags:**
- `std`: Enable standard library (default for host crates)
- `tokio-rustls`: Enable async TLS client (vefas-core)
- `cuda`: Enable CUDA acceleration for RISC0 (vefas-risc0)

### Working with Guest Programs

**Modifying SP1 Guest:**
1. Edit `crates/vefas-sp1/program/src/main.rs`
2. Rebuild: `cd crates/vefas-sp1/program && cargo prove build`
3. Test: `cargo test -p vefas-sp1`

**Modifying RISC0 Guest:**
1. Edit `crates/vefas-risc0/methods/guest/src/main.rs`
2. Rebuild: `cargo build -p vefas-risc0-methods`
3. Test: `cargo test -p vefas-risc0`

**Debugging Guest Programs:**
- Use `eprintln!` macro (mapped to `sp1_zkvm::io::commit` or `risc0_zkvm::guest::env::log`)
- Check cycle counts with `println!("cycle-tracker-start: label")` (SP1) or `env::cycle_count()` (RISC0)
- Review execution reports in host prover logs

### TLS Capture Implementation

The custom rustls provider (`vefas-rustls`) captures:
- Ephemeral private keys during key exchange
- All handshake messages (ClientHello, ServerHello, Certificate, etc.)
- Certificate chains
- Application data (encrypted request/response)

**Key files:**
- `vefas-rustls/src/capture.rs`: Capture infrastructure
- `vefas-rustls/src/capturing.rs`: Key exchange group wrappers for ephemeral key capture
- `vefas-core/src/client.rs`: VefasClient integration with rustls

**Safety:** Ephemeral key capture is only enabled in debug builds via `SafeCaptureHandle`

## API Endpoints

### POST /api/v1/requests
Generate zkTLS proof for HTTPS request

**Request:**
```json
{
  "method": "GET",
  "url": "https://example.com/api/endpoint",
  "headers": {"Authorization": "Bearer token"},
  "body": "optional request body",
  "proof_platform": "risc0"  // or "sp1"
}
```

**Response:**
```json
{
  "proof": {
    "claim": {
      "domain": "example.com",
      "timestamp": 1678886400,
      "http_status": 200,
      "request_hash": "...",
      "response_hash": "..."
    },
    "proof_data": "...",
    "platform": "risc0"
  }
}
```

### POST /api/v1/verify
Verify zkTLS proof

### GET /api/v1/health
Health check and platform availability

## References

- TLS 1.3 Specification: RFC 8446
- Supported Cipher Suites: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- Key Exchange: ECDHE with X25519 or P-256
- Certificate Validation: ECDSA, Ed25519, RSA

## Important Notes

- **Never commit secrets**: Client private keys are ephemeral and captured only during TLS handshake
- **zkVM resource constraints**: Keep guest programs lean (max 1MB HTTP body, 64KB handshake transcript)
- **Workspace dependencies**: Centralized in root `Cargo.toml` `[workspace.dependencies]`
- **Platform detection**: Use `#[cfg(feature = "std")]` for host-only code, `#![no_std]` for guest programs
