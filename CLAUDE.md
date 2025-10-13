# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

VEFAS (Verifiable Execution Framework for Agents) is a zkTLS client that generates cryptographic proofs of HTTPS requests and responses. It enables AI agents to prove they performed external actions (e.g., "Email sent") without relying on trust, MPC, or notaries.

**Key Innovation**: Two-layer verification architecture:
1. **Layer 1 (zkVM Receipt)**: Fast cryptographic proof validation using zkVM (RISC0 or SP1)
2. **Layer 2 (TLS Validation)**: Comprehensive validation of Merkle proofs, certificates, and handshake integrity

**Supported Platforms**: RISC0 and SP1 zkVMs with CUDA acceleration support

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
cargo test -p vefas-node
cargo test -p vefas-crypto

# Run integration tests (requires 180s timeout for proof generation)
cargo test -p vefas-node --test integration_tests --release --features cuda

# Run specific test
cargo test test_e2e_proof_generation_and_verification_risc0
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

### Running the VEFAS Node
```bash
# Start the unified VEFAS node server (port 8080)
cargo run -p vefas-node --release

# With CUDA acceleration (requires CUDA 12, 24GB+ VRAM)
cargo run -p vefas-node --release --features cuda

# Test with curl
curl -X POST http://127.0.0.1:8080/api/v1/requests \
  -H "Content-Type: application/json" \
  -d '{"method": "GET", "url": "https://example.com", "proof_platform": "risc0"}'
```

## Architecture

### Crate Organization

**Core Infrastructure:**
- `vefas-types`: Platform-agnostic no_std types for zkTLS verification (canonical bundles, proof claims)
- `vefas-core`: Production HTTP client with TLS capture (`VefasClient`)
- `vefas-node`: Unified HTTP execution and proof verification service with REST API
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
HTTP Request → VefasClient → TLS Handshake Capture → VefasCanonicalBundle + Merkle Tree
                                                              ↓
                                                    zkVM Guest Program
                                                    (SP1 or RISC0)
                                                              ↓
                                                    Cryptographic Verification
                                                              ↓
                                                    VefasProofClaim + zkVM Receipt
                                                              ↓
                                                    VerifierService (2-Layer)
                                                              ↓
                                                    ValidationResult (valid/invalid)
```

### Verification Flow (2-Layer Architecture)

**Host Proof Generation:**
1. `VefasClient` captures TLS 1.3 handshake and HTTP exchange
2. `transcript_bundle.rs` creates `VefasCanonicalBundle` with real extracted data
3. `merkle_tree.rs` builds Merkle tree for selective disclosure
4. zkVM prover generates cryptographic proof (SP1 or RISC0)
5. Returns: `{proof_data, claim, bundle}`

**VerifierService Validation:**
1. **Layer 1: zkVM Receipt Verification** (fast, cryptographic)
   - Verify proof using platform-specific prover (SP1 or RISC0)
   - Validate proof was generated by trusted zkVM program (ELF ID / VK)
   - Extract verified claim from proof

2. **Layer 2: TLS Validation** (comprehensive)
   - Validate Merkle proofs for selective disclosure fields
   - Verify certificate chain with bundled root certificates
   - Validate HandshakeProof integrity:
     - `handshake_proof.server_random == bundle.server_random`
     - `handshake_proof.cert_fingerprint == bundle.cert_fingerprint`
     - `handshake_proof.tls_version == bundle.tls_version`
   - Verify HTTP request/response integrity
   - Confirm domain binding and timestamp

**Critical Path:**
- Host creates HandshakeProof in `transcript_bundle.rs` (bundle)
- Host creates HandshakeProof in `merkle_tree.rs` (Merkle tree)
- zkVM extracts HandshakeProof from Merkle tree
- zkVM validates: extracted HandshakeProof == bundle HandshakeProof
- VerifierService validates: Merkle tree integrity + certificate chain + TLS handshake

**If ANY step fails, validation returns `invalid: true` with error details.**

**VefasCanonicalBundle** (vefas-types/src/bundle.rs):
- Contains complete TLS session data: ClientHello, ServerHello, Certificate chain, encrypted request/response
- Includes ephemeral private key (captured during handshake for debug/verification)
- Domain, timestamp, and verifier nonce for binding
- Merkle root and proofs for selective disclosure
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
- `vefas-node`: REST API server
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
- `vefas-crypto/src/bundle_parser.rs`: Bundle parsing and extraction utilities
- `vefas-crypto/src/validation.rs`: Certificate and handshake validation
- Guest programs use these utilities for verification

### HandshakeProof Consistency - CRITICAL

**HandshakeProof is created in TWO locations** and must be identical:

1. **`vefas-rustls/src/transcript_bundle.rs`** (Lines 406-446)
   - Creates HandshakeProof for VefasCanonicalBundle
   - Extracts server_random, cert_fingerprint, tls_version

2. **`vefas-rustls/src/merkle_tree.rs`** (Lines 149-218)
   - Creates HandshakeProof for Merkle tree field serialization
   - Must use IDENTICAL extraction logic

**Required Data Extraction Pattern:**

```rust
// 1. Extract server_random from ServerHello (skip 4-byte handshake header)
let server_random = if !server_hello.is_empty() && server_hello.len() > 4 {
    use vefas_crypto::bundle_parser::extract_server_random;
    let server_hello_body = &server_hello[4..]; // Skip handshake header
    extract_server_random(server_hello_body)
        .ok()
        .flatten()
        .unwrap_or([0u8; 32])
} else {
    [0u8; 32]
};

// 2. Compute cert_fingerprint using NativeCryptoProvider
let cert_fingerprint = if !bundle.cert_chain.is_empty() {
    use vefas_crypto::Hash;
    let crypto = NativeCryptoProvider::new();
    crypto.sha256(&bundle.cert_chain)
} else {
    [0u8; 32]
};

// 3. Use consistent TLS version default (0x0304 for TLS 1.3)
let tls_version = bundle.tls_version.unwrap_or(0x0304);
```

**ServerHello Format (RFC 8446):**
```
[type(1)][length(3)][legacy_version(2)][random(32)][session_id_len(1)]...
        ^
        4-byte handshake header to skip
```

**Why This Matters:**
- Host creates Merkle tree with HandshakeProof
- Host creates bundle with HandshakeProof
- zkVM guest extracts HandshakeProof from Merkle tree
- zkVM guest validates: `handshake_proof.server_random == bundle.server_random`
- If ANY field differs, validation fails with `VERIFICATION_FAILURE`

**Common Pitfall:**
Using hardcoded defaults (e.g., `[0u8; 32]` for server_random) or inconsistent TLS version defaults (0x0303 vs 0x0304) will cause Merkle proof validation failures.

## Development Guidelines

### Adding New Cryptographic Primitives

1. Define trait in `vefas-crypto/src/traits.rs`
2. Implement for native in `vefas-crypto-native/src/provider.rs`
3. Implement for SP1 in `vefas-crypto-sp1/src/lib.rs` (using SP1 precompiles)
4. Implement for RISC0 in `vefas-crypto-risc0/src/lib.rs` (using RISC0 precompiles)

Example pattern:
```rust
// vefas-crypto/src/traits.rs
pub trait NewCryptoOp {
    fn perform(&self, input: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

// vefas-crypto-native/src/provider.rs
impl NewCryptoOp for NativeCryptoProvider {
    fn perform(&self, input: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // Use aws-lc-rs
    }
}

// vefas-crypto-sp1/src/lib.rs
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

**Integration Tests**: `crates/vefas-node/tests/integration_tests.rs`
- Test full proof generation and verification flow
- Test both SP1 and RISC0 platforms
- Use `#[tokio::test(flavor = "multi_thread")]` and `#[serial]` for zkVM tests

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

**Merkle Proofs:**
- Reduces zkVM circuit size by 90%+
- Enables selective field verification
- Computed on host, verified in guest

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
- `cuda`: Enable CUDA acceleration for RISC0 and SP1
- `sp1`: Enable SP1 zkVM support (default in vefas-node)
- `risc0`: Enable RISC0 zkVM support (default in vefas-node)

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
- `vefas-rustls/src/transcript_bundle.rs`: Converts captured data to VefasCanonicalBundle (creates HandshakeProof)
- `vefas-rustls/src/merkle_tree.rs`: Builds Merkle tree for selective disclosure (creates HandshakeProof)
- `vefas-core/src/client.rs`: VefasClient integration with rustls

**Safety:** Ephemeral key capture is only enabled in debug builds via `SafeCaptureHandle`

**Production-Grade Data Extraction:**
All placeholder/mock data has been replaced with real captured values:
- `server_random`: Extracted from ServerHello (skip 4-byte handshake header)
- `cert_fingerprint`: SHA-256 hash of certificate chain using NativeCryptoProvider
- `tls_version`: Actual TLS version from session (defaults to 0x0304 for TLS 1.3)

**Unified Cryptographic Operations:**
Use `NativeCryptoProvider` (from `vefas-crypto-native`) for all host-side cryptographic operations:
- Ensures consistency across bundle creation and Merkle tree generation
- Provides testable, auditable crypto implementations
- Aligns with trait-based architecture

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
  "success": true,
  "proof": {
    "platform": "risc0",
    "proof_data": "base64_encoded_proof",
    "claim": {
      "domain": "example.com",
      "timestamp": 1678886400,
      "status_code": 200,
      "request_hash": "...",
      "response_hash": "..."
    },
    "execution_metadata": {
      "cycles": 1234567,
      "proof_time_ms": 1500
    }
  },
  "bundle": {
    "client_hello": "...",
    "server_hello": "...",
    "cert_chain": "..."
  },
  "http_response": {
    "status": 200,
    "headers": {},
    "body": "response content"
  }
}
```

### POST /api/v1/verify
Verify zkTLS proof with 2-layer validation

**Request:**
```json
{
  "proof": {
    "platform": "risc0",
    "proof_data": "base64_encoded_proof",
    "claim": {...},
    "execution_metadata": {...}
  },
  "bundle": {
    "client_hello": "...",
    "server_hello": "...",
    "cert_chain": "..."
  }
}
```

**Response:**
```json
{
  "success": true,
  "verification_result": {
    "valid": true,
    "platform": "risc0",
    "verified_claim": {...},
    "verification_metadata": {
      "verification_time_ms": 50
    },
    "validation_errors": [],
    "merkle_proofs_validated": 6,
    "claim_verification_passed": true
  }
}
```

### GET /api/v1/health
Health check and platform availability

### GET /
Service information and API documentation

## Debugging Common Issues

### Validation Errors

#### Error: "Certificate fingerprint mismatch"
**Cause**: `bundle.cert_fingerprint` contains hardcoded zeros or incorrect hash
**Fix**: Ensure both `transcript_bundle.rs` and `merkle_tree.rs` compute cert_fingerprint identically:
```rust
let cert_fingerprint = if !cert_chain.is_empty() {
    use vefas_crypto::Hash;
    let crypto = NativeCryptoProvider::new();
    crypto.sha256(&cert_chain)
} else {
    [0u8; 32]
};
```

#### Error: "TLS version mismatch: claim=1.3, expected=1.2"
**Cause**: Inconsistent TLS version defaults between files
**Fix**: Use `0x0304` (TLS 1.3) consistently in both `transcript_bundle.rs` and `merkle_tree.rs`:
```rust
let tls_version = bundle.tls_version.unwrap_or(0x0304);
```

#### Error: "Server random in HandshakeProof does not match bundle server random"
**Cause**: Incorrect ServerHello parsing - forgot to skip 4-byte handshake header
**Fix**: Always skip handshake header before extracting server_random:
```rust
let server_hello_body = &server_hello[4..]; // Skip [type(1)][length(3)]
extract_server_random(server_hello_body)
```

#### Error: "Merkle proof validation failed for field_id: 11"
**Cause**: field_id 11 = TlsVersion has different defaults in different files
**Fix**: Ensure ALL locations use identical TLS version default (0x0304)
- Check `transcript_bundle.rs` (bundle creation)
- Check `merkle_tree.rs` (Merkle tree HandshakeProof creation)
- Check `merkle_tree.rs` (Merkle leaf TlsVersion field)

### 2-Layer Verification Architecture

**All verification happens in VerifierService** - do NOT call ProverService separately:

```rust
// ❌ WRONG - Redundant ProverService call
let proof_result = prover_service.verify_proof(&proof_data).await?;
let validation_result = verifier_service.validate_zk_proof(&proof_bytes).await?;

// ✅ CORRECT - Single VerifierService call performs both layers
let validation_result = verifier_service.validate_zk_proof(
    &proof_bytes,
    &platform,
    &bundle,
).await?;
```

**Layer 1**: zkVM receipt verification (fast, cryptographic)
**Layer 2**: TLS validation (Merkle proofs, certificates, handshake integrity)

### Integration Test Failures

#### Error: "blocking call within async context"
**Cause**: SP1/RISC0 CUDA provers use blocking operations requiring multi-threaded runtime
**Fix**: Add `#[tokio::test(flavor = "multi_thread")]` to all tests

#### Error: "docker: Error response from daemon: Conflict. The container name '/sp1-gpu' is already in use"
**Cause**: Multiple tests spawning containers in parallel
**Fix**:
1. Add `serial_test = "3.0"` to Cargo.toml dependencies
2. Add `#[serial]` annotation to all integration tests
3. Create `.cargo/config.toml`:
```toml
[test]
timeout = 180  # 3 minutes minimum for proof generation
```

### RISC0 vs SP1 Architectural Differences

**SP1**: Prover can be stored in ProverService (initialized in `new()`)
```rust
pub struct ProverService {
    sp1_prover: Option<Arc<Mutex<VefasSp1Prover>>>,  // Thread-safe for CUDA
}
```

**RISC0**: Prover uses `Rc<dyn Prover>` which is NOT Send - cannot store in struct
```rust
// ❌ This won't compile - Rc is not Send
pub struct ProverService {
    risc0_prover: Option<VefasRisc0Prover>,  // Contains Rc<dyn Prover>
}

// ✅ Initialize on-demand per proof generation
impl VefasRisc0Prover {
    pub fn generate_zk_proof(&self, bundle: &VefasCanonicalBundle) -> VefasResult<VefasRisc0Proof> {
        let prover = default_prover();  // Create fresh prover each time
        // ...
    }
}
```

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
- **HandshakeProof consistency**: TWO creation locations must use identical extraction logic
- **Unified verification**: Always use VerifierService (not ProverService) for verification endpoints
