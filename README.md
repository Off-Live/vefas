# **VEFAS: Verifiable Execution Framework for Agents**

*A revolutionary zkTLS client using host-rustls + guest-verifier architecture for optimal proof efficiency*

---

## **1. Vision & Goal**

AI Agents often hallucinate external actions (e.g., claiming "Email sent" without actually sending it).
**VEFAS** eliminates this by making external requests **cryptographically verifiable**:

> At time `T`, with a given request `{method, headers, query, body}`,
> I sent it to resource `https://abc.xyz` over TLS,
> and received the response `{status, payload}`.

The proof is portable and verifiable by anyone — **no MPC, no notary, no trust in gateway**.

---

## **2. Revolutionary Architecture: Host-Rustls + Guest-Verifier**

### **Optimal Separation: Implementation vs Verification**

VEFAS uses a **fundamentally superior architecture** that separates TLS implementation from verification:

* **AI Agent** → issues command (e.g., send email).
* **VEFAS Gateway (Host - std)**:
    * **Real TLS**: Full `rustls` implementation for actual network connections
    * **Bundle Capture**: Extract exact wire data (handshake, keys, encrypted records)
    * **Canonical Format**: Create deterministic bundle for guest verification
* **zkVM Guest (no_std + alloc)**:
    * **Minimal Verifier**: Purpose-built TLS verifier (~1000 lines vs ~50k rustls)
    * **Direct Precompiles**: SHA256, ECDSA P-256 via SP1/RISC0 precompiles
    * **Pure Rust Crypto**: AES-GCM, ChaCha20-Poly1305, X25519 fallbacks
    * **Deterministic Verification**: Process canonical bundle, output proof claims
* **Verifier (Node / Blockchain / API)**:
    * Validates zkProof from chosen platform
    * Confirms execution actually happened

**🎯 Key Innovation**: Orders of magnitude cheaper proofs through minimal guest verifier + direct precompile usage

---

## **3. TLS Session Verification Flow (Host-Guest Architecture)**

### Step 1 — **Real TLS Connection (Host)**

* **Host**: Establish real TLS connection using full `rustls` implementation
* **Bundle Capture**: Extract exact wire data via `vefas-bundler`:
  * Raw handshake messages (ClientHello, ServerHello, Certificate, etc.)
  * Client ephemeral private key from ECDHE
  * Encrypted TLS records (request/response)
  * Certificate chain (DER bytes)

### Step 2 — **Canonical Bundle Creation (Host)**

* **Deterministic Format**: Create `VefasCanonicalBundle` with exact byte representation
* **No Interpretation**: Raw captured data, no parsing or transformation
* **Metadata**: Add domain, timestamp, nonce for verification context

### Step 3 — **Minimal TLS Verification (Guest)**

* **Guest**: `vefas-verifier` processes canonical bundle deterministically:
  * Parse handshake messages (minimal parsing logic)
  * Compute transcript hash using **SHA256 precompile**
  * Derive ECDHE shared secret (X25519 pure Rust or precompile)
  * Run HKDF key schedule using **SHA256 precompile**
  * Decrypt TLS records using pure Rust AES-GCM/ChaCha20-Poly1305

### Step 4 — **Cryptographic Verification (Guest)**

* **Certificate Verification**: Verify signatures using **ECDSA P-256 precompile**
* **Handshake Integrity**: Verify server Finished message
* **HTTP Parsing**: Extract and validate plaintext HTTP request/response

### Step 5 — **Proof Generation (Guest)**

* zkVM commits structured claim:

  ```json
  {
    "domain": "abc.xyz",
    "request_commitment": "...",
    "response_commitment": "...",
    "status_code": 200,
    "tls_version": "1.3",
    "cipher_suite": "TLS_AES_256_GCM_SHA384",
    "certificate_chain_hash": "...",
    "handshake_transcript_hash": "...",
    "timestamp": 1234567890,
    "execution_metadata": {
      "cycles": 1000000,
      "memory_usage": 2048,
      "execution_time_ms": 150,
      "platform": "sp1|risc0",
      "proof_time_ms": 75
    }
  }
  ```

### Step 6 — **Verification**

* Verifier validates proof using platform-specific verification
* Confirms: request, response, domain, cert chain, execution metadata

---

## **4. Implementation Details**

### **4.1. Revolutionary Crate Structure**

```
VEFAS Workspace

├── crates/
│   ├── vefas-types/             # Shared no_std types (bundle, errors, http, tls)
│   ├── vefas-crypto/            # Crypto traits and error types (no_std)
│   ├── vefas-crypto-native/     # Pure-Rust crypto provider (dev/CI)
│   ├── vefas-crypto-sp1/        # SP1 crypto provider bindings
│   ├── vefas-crypto-risc0/      # RISC0 crypto provider bindings
│   ├── vefas-rustls/            # rustls CryptoProvider with ephemeral key capture
│   ├── vefas-core/              # Host TLS+HTTP client; builds VefasCanonicalBundle
│   ├── vefas-gateway/           # REST API server: /requests, /verify, /health
│   ├── vefas-sp1/               # SP1 integration (guest program + host script)
│   │   ├── program/             # SP1 guest: verifies bundle, emits claim
│   │   └── script/              # SP1 host orchestration
│   └── vefas-risc0/             # RISC0 integration (methods, guest, host)
│
└── tests/                       # Root integration tests (spawn gateway, e2e)
```

Notes:
- Host TLS capture uses `crates/vefas-rustls` as the `rustls` CryptoProvider to deterministically capture the client ephemeral scalar.

### **4.2. Architecture Benefits**

**🚀 Proof Efficiency:**
- **10-100x cheaper proofs**: Minimal verifier (~1000 lines) vs full rustls (~50k+ lines)
- **Direct precompiles**: SHA256, ECDSA P-256 optimization via zkVM precompiles
- **Minimal instruction count**: Purpose-built verification vs general TLS implementation

**🧠 Engineering Reality:**
- **Clear separation**: Host uses rustls + vefas-rustls provider, guest uses minimal verifier
- **Unified host client**: Single client.rs file with complete TLS workflow
- **Production-grade host**: Battle-tested rustls with custom vefas-rustls provider
- **Maintainable**: Small, focused verifier is easier to audit and test
- **zkVM optimized**: Deterministic verification without complex state machines

**⚡ Performance:**
- **Host**: Full rustls + aws-lc-rs for real TLS connections (std environment)
- **Guest**: Minimal verifier + precompiles (no_std + alloc)
- **Bundle**: Canonical format extracted directly from rustls session data
- **No custom crypto**: Eliminates host-side crypto abstractions, uses proven rustls stack

### **4.3. Canonical Bundle Format**

The canonical bundle is created by extracting data directly from rustls session state:

```rust
#[derive(Serialize, Deserialize)]
pub struct VefasCanonicalBundle {
    // Protocol compatibility
    pub version: u16,

    // Raw handshake messages (extracted from rustls ClientConnection)
    pub client_hello: Vec<u8>,
    pub server_hello: Vec<u8>,
    pub certificate_msg: Vec<u8>,
    pub certificate_verify_msg: Vec<u8>,
    pub server_finished_msg: Vec<u8>,

    // Cryptographic materials (from rustls session)
    pub client_private_key: [u8; 32],    // ECDHE private key from provider
    pub certificate_chain: Vec<Vec<u8>>, // DER encoded certificates

    // Application data (TLS records from rustls stream)
    pub encrypted_request: Vec<u8>,      // TLS record
    pub encrypted_response: Vec<u8>,     // TLS record

    // Verification metadata
    pub domain: String,
    pub timestamp: u64,
    pub expected_status: u16,
    pub verifier_nonce: [u8; 32],
}
```

Constraints (enforced in `crates/vefas-types/src/bundle.rs`):
- Handshake messages ≤ 16 KiB; TLSCiphertext records ≤ 16 KiB + overhead.
- Certificate chain total size ≤ 64 KiB; record-layer fields validated.

### **4.4. Crypto Provider Strategy**

**🔑 Guest-Only Crypto Providers with Precompile Optimization:**

Host side uses rustls + aws-lc-rs (no custom crypto providers needed). Guest side uses platform-specific crypto providers:

```rust
// vefas-crypto trait abstractions (guest-only)
pub trait Hash {
    fn sha256(data: &[u8]) -> [u8; 32];   // SP1/RISC0 precompile
    fn sha384(data: &[u8]) -> [u8; 48];   // SP1/RISC0 precompile
}

pub trait Ecdsa {
    fn verify_p256(sig: &[u8], msg: &[u8], pk: &[u8]) -> bool; // Precompile
}

pub trait Aead {
    fn aes_gcm_decrypt(...) -> Result<Vec<u8>>;        // Pure Rust or precompile
    fn chacha20poly1305_decrypt(...) -> Result<Vec<u8>>; // Pure Rust or precompile
}
```

**Provider implementations (guest-only):**
- **vefas-crypto-sp1**: Direct SP1 crypto library usage with precompiles
- **vefas-crypto-risc0**: Direct RISC0 crypto library usage with precompiles
- **vefas-crypto-native**: Pure Rust for testing, development, CI/CD, and benchmarking

---

## **5. Revolutionary Advantages**

**🚀 Proof Economics:**
- **10-100x cheaper proofs**: Minimal guest verifier vs full rustls in circuit
- **Direct precompile usage**: SHA256, ECDSA P-256 optimization
- **Optimal instruction count**: Purpose-built verification logic

**🧠 Engineering Excellence:**
- **Separation of concerns**: Host uses rustls + aws-lc-rs, guest uses minimal verifier
- **Unified host implementation**: Single client.rs file with complete TLS workflow
- **Production-grade host**: Battle-tested rustls with aws-lc-rs crypto provider
- **Maintainable architecture**: Small, auditable verifier (~1000 lines)
- **zkVM best practices**: Deterministic verification without complex state machines

**⚡ Performance Benefits:**
- **Host efficiency**: Full rustls + aws-lc-rs for real TLS connections
- **Guest optimization**: Minimal verifier + direct precompiles
- **Clear boundaries**: Canonical bundle format extracted from rustls session data
- **No host crypto abstractions**: Eliminates custom crypto, uses proven rustls stack

**🔧 Developer Experience:**
- **Easier debugging**: Clear host/guest separation with rustls on host
- **Simpler testing**: Independent verification logic, real TLS on host
- **Better auditability**: Focused, purpose-built components
- **Proven TLS stack**: Uses battle-tested rustls + aws-lc-rs on host side

### **4.3. Dependency Architecture Clarifications**

**✅ Host vs Guest SDK Usage:**
- **vefas-prover**: Uses `sp1-sdk`, `risc0-zkvm` (host SDKs - std)
- **Guest programs**: Use `sp1-zkvm`, `risc0-zkvm` (guest runtimes - no_std)

**✅ no_std Compatibility:**
- **vefas-bundler** (std) can depend on **vefas-types** (no_std) ✓
- `no_std` means "can work without std", not "cannot work with std"
- Upward compatibility: no_std crates work in std environments

**✅ Crypto Provider Simplification:**
- **vefas-crypto-sp1**: Single `lib.rs` using SP1 crypto libraries directly
- **vefas-crypto-risc0**: Single `lib.rs` using RISC0 crypto libraries directly
- **vefas-crypto-native**: Pure Rust for testing, development, CI/CD

### **4.4. How Crates Work Together**

**🔧 Data Flow and Responsibilities:**

**1. vefas-types (Foundation)**
- Defines all shared data structures used across the system
- `VefasCanonicalBundle`: TLS session data extracted from rustls
- `VefasProofClaim`: Structured proof output with commitments
- `no_std` compatible for use in both host and guest environments

**2. vefas-core (Unified Host HTTP/TLS Client)**
- Single unified client.rs file (~800-1000 lines) with complete TLS workflow
- Uses rustls + aws-lc-rs for real TLS connections (std only)
- Integrates TLS connection, HTTP processing, data extraction, and bundle creation
- Extracts canonical bundle data directly from rustls session state
- Creates deterministic bundle format for guest verification

**3. vefas-crypto-sp1/risc0/native (Guest Crypto Providers)**
- Platform-specific crypto implementations for zkVM environments
- Use direct precompiles (SP1/RISC0) or pure Rust (native)
- Handle TLS verification crypto operations (AEAD, HKDF, signatures)
- Only used in guest environment, not on host

**4. vefas-verifier (Guest TLS Verifier)**
- Minimal TLS verification logic (~1000 lines)
- Processes canonical bundle from rustls session data
- Uses platform-specific crypto providers
- Generates proof claims for zkVM commitment

**5. Platform Integration (vefas-sp1, vefas-risc0)**
- **Host (std)**: Orchestrates proof generation using platform SDKs
- **Guest (no_std)**: Runs TLS verification in zkVM using minimal verifier
- Bridges between real network operations and cryptographic proofs

**6. vefas-gateway (Production Service)**
- REST API and CLI interface for proof generation
- Chooses appropriate platform (SP1 or RISC0) based on configuration
- Handles proof verification and response formatting

**🎯 Architecture Benefits:**
- ✅ **Host simplification** - rustls + aws-lc-rs eliminates custom crypto
- ✅ **Guest optimization** - minimal verifier with direct precompiles
- ✅ **Clear separation** - host handles complexity, guest handles verification
- ✅ **Proven security** - battle-tested rustls TLS implementation on host
- ✅ **Optimal proofs** - minimal verification logic in zkVM

### **4.5. Precompile Integration Within Single Provider**

| Precompile        | SP1 Usage | RISC0 Usage | Purpose |
| ----------------- | --------- | ----------- | ------- |
| **sha256/sha384** | ✅ | ✅ | Transcript hash, Finished, HKDF, cert digest |
| **aes-gcm**       | ✅ | ✅ | Encrypt request / decrypt response |
| **secp256r1**     | ✅ | ✅ | ECDHE shared secret, ECDSA signatures |
| **ed25519**       | ✅ | ✅ | Optional cert signatures |
| **rsa**           | ✅ | ✅ | Legacy TLS certs (optional) |
| **bigint ops**    | ✅ | ✅ | Modular arithmetic in crypto ops |

**Documentation References:**
- SP1 Precompiles: https://docs.succinct.xyz/docs/sp1/optimizing-programs/precompiles
- RISC0 Precompiles: https://dev.risczero.com/api/zkvm/precompiles

### **4.6. Unified Data Flow with rustls + aws-lc-rs**

**Complete VEFAS Workflow:**

**Host Operations (std):**
```rust
// vefas-core with rustls + vefas-rustls provider
use vefas_core::VefasClient;

let client = VefasClient::new()?;
let bundle = client
    .execute_request(
        "GET",
        "https://api.example.com/data",
        None,   // optional headers: &[(&str, &str)]
        None    // optional body bytes
    )
    .await?;
```

**Guest Verification (no_std + alloc):**
```rust
// vefas-verifier with platform-specific crypto
#![no_std]
extern crate alloc;

use vefas_verifier::TlsVerifier;
use vefas_crypto_sp1::SP1CryptoProvider;

pub fn verify_bundle(bundle: VefasCanonicalBundle) -> VefasProofClaim {
    let provider = SP1CryptoProvider::default();
    let verifier = TlsVerifier::new(provider);
    verifier.verify_bundle(&bundle)
}
```

**Unified Integration Pattern:**
```
# Same provider, same rustls, different platforms
vefas-sp1/                # SP1 zkVM program and host integration
├── program/              # SP1 guest program (no_std)
│   └── src/main.rs       # SP1 zkVM entry point using rustls + vefas-rustls-sp1
├── script/               # SP1 host integration (std)
│   └── src/main.rs       # SP1 proof generation and verification
└── src/
    ├── lib.rs            # SP1VefasProver public API
    └── prover.rs         # SP1 proof orchestration

vefas-risc0/              # RISC0 zkVM program and host integration
├── methods/guest/        # RISC0 guest program (no_std)
│   └── src/main.rs       # RISC0 zkVM entry point using rustls + vefas-rustls-risc0
└── src/
    ├── lib.rs            # RISC0VefasProver public API
    ├── main.rs           # RISC0 proof generation and verification
    └── prover.rs         # RISC0 proof orchestration
```

**🎯 Key Benefits:**
- **Host simplification** - rustls + aws-lc-rs eliminates custom crypto abstractions
- **Unified client** - single client.rs file with complete TLS workflow
- **Guest optimization** - minimal verifier with direct precompiles
- **Clear separation** - host handles TLS complexity, guest handles verification
- **Proven security** - battle-tested rustls TLS implementation on host side
- **Optimal proofs** - minimal verification logic in zkVM for cost efficiency

---

### **4.7. Gateway API (current)**

Endpoints
- POST `/api/v1/requests`: Execute an HTTPS request and generate a proof
- POST `/api/v1/verify`: Verify a proof and return the verified claim
- GET `/api/v1/health`: Report service health and available platforms
- GET `/`: Service info

Request schema: POST /api/v1/requests
```json
{
  "method": "GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH",
  "url": "https://host/path?query",
  "headers": {"header-name": "value"},
  "body": "<base64-encoded-bytes>",
  "proof_platform": "sp1|risc0",
  "timeout_ms": 30000
}
```

Response
```json
{
  "success": true,
  "http_response": {
    "status_code": 200,
    "headers": {},
    "body": ""
  },
  "proof": {
    "platform": "sp1|risc0",
    "proof_data": "<base64>",
    "claim": {
      "domain": "example.com",
      "method": "GET",
      "path": "/path",
      "request_hash": "…",
      "response_hash": "…",
      "timestamp": 1234567890,
      "status_code": 200,
      "tls_version": "1.3",
      "cipher_suite": "TLS_AES_128_GCM_SHA256",
      "certificate_chain_hash": "…",
      "handshake_transcript_hash": "…"
    },
    "execution_metadata": {
      "cycles": 0,
      "memory_usage": 0,
      "execution_time_ms": 0,
      "proof_time_ms": 0,
      "platform": "sp1|risc0"
    }
  },
  "session_id": "…"
}
```

Request schema: POST /api/v1/verify
```json
{
  "proof": { /* same structure as above */ },
  "expected_claim": { /* optional; same shape as claim */ }
}
```

Response
```json
{
  "success": true,
  "verification_result": {
    "valid": true,
    "platform": "sp1|risc0",
    "verified_claim": { /* claim */ },
    "verification_metadata": {
      "verification_time_ms": 12,
      "verifier_version": "0.1.0",
      "verified_at": 1712345678
    }
  }
}
```

Validation
- HTTPS URL only; timeout 1s–300s; body must be valid base64; header size limits.
- Proof data must be base64; platform must be `sp1` or `risc0`.

---

### **4.8. Host ↔ Guest zkVM Sequence Diagram**

```mermaid
sequenceDiagram
    autonumber
    participant User as User / Client
    participant Gateway as VEFAS Gateway (Host, std)
    participant Core as vefas-core (rustls + vefas-rustls)
    participant SP1 as SP1 zkVM Guest (no_std)
    participant R0 as RISC0 zkVM Guest (no_std)
    participant Verifier as Verifier (Host / Chain / API)

    User->>Gateway: POST /api/v1/requests { method, url, headers, body, proof_platform }
    Gateway->>Core: Execute HTTPS over TLS 1.3
    Core-->>Core: Capture handshake, certs, records, ephemeral key
    Core-->>Gateway: VefasCanonicalBundle

    alt proof_platform == "sp1"
        Gateway->>SP1: Run guest with bundle (stdin)
        SP1-->>SP1: Verify TLS, decrypt HTTP, compute claims
        SP1-->>Gateway: Proof { proof_data, claim, execution_metadata }
    else proof_platform == "risc0"
        Gateway->>R0: Run guest with bundle (stdin)
        R0-->>R0: Verify TLS, decrypt HTTP, compute claims
        R0-->>Gateway: Proof { receipt_data, claim, execution_metadata }
    end

    Gateway-->>User: { http_response, proof }

    User->>Gateway: POST /api/v1/verify { proof, expected_claim? }
    alt platform == "sp1"
        Gateway->>Gateway: Verify SP1 proof
    else platform == "risc0"
        Gateway->>Gateway: Verify RISC0 receipt
    end
    Gateway-->>User: { valid, verified_claim, verification_metadata }

    Note over Core,SP1: Clean separation: host implements TLS; guest verifies it
```

---

## **5. TDD Development Requirements**

### **5.1. Strict Workflow**

* **Red → Green → Refactor**:
    * Write failing test first.
    * Implement minimal code to pass.
    * Refactor cleanly.
* No production code without a test.

### **5.2. Test Directory Structure**

```
tests/
├── fixtures/                    # Reusable test data
│   ├── certificates/           # X.509 certificates (DER format)
│   ├── network/               # TLS handshake transcripts
│   └── samples/               # Sample inputs/outputs
├── integration/               # Full pipeline tests
│   ├── gateway/               # Gateway API integration tests
│   ├── network/               # Real network integration tests
│   └── platforms/            # Cross-platform integration tests
└── [crate-specific tests]     # Unit tests within each crate
```

### **5.3. Test Levels**

* **Unit Tests** (within each crate)
    * **rustls Provider**: Single provider testing across all platforms
    * **TLS Operations**: rustls-based handshake, certificate, HTTP processing
    * **Platform Optimization**: SP1/RISC0 precompile routing validation

* **Integration Tests** (root level)
    * **Gateway API**: REST endpoints, CLI commands, configuration
    * **Network Integration**: Real HTTPS requests via rustls
    * **Cross-Platform**: SP1 vs RISC0 consistency with same provider
    * **End-to-End**: Full rustls + zkProof pipeline

* **Platform-Specific Tests**
    * **SP1 Guest Tests**: rustls + vefas-rustls-sp1 in SP1 zkVM
    * **RISC0 Guest Tests**: rustls + vefas-rustls-risc0 in RISC0 zkVM
    * **Proof Generation**: Platform-specific proof creation
    * **Proof Verification**: Platform-specific proof validation

* **Fixtures**
    * **TLS 1.3 Sessions**: Real rustls session captures
    * **Certificate Chains**: ECDSA, Ed25519, RSA certificates
    * **HTTP Requests/Responses**: Sample API calls over rustls TLS
    * **Provider Test Vectors**: Crypto operation validation data

---

## **6. Development Principles**

### **6.1. TLS Knowledge Sources**
Always refer to these authoritative sources for TLS knowledge:
- **RFC 8446 (TLS 1.3)**: https://datatracker.ietf.org/doc/html/rfc8446
- **RFC 8448 (TLS 1.3 Handshake Traces Sample)**: https://datatracker.ietf.org/doc/html/rfc8448
- **TLS1.3 bytes explained**: https://tls13.xargs.org/#open-all
- **rustls Documentation**: https://docs.rs/rustls/latest/rustls/

### **6.2. Sequential Thinking (MCP style)**
Always break down rustls TLS verification step-by-step:
1. **Provider Setup** → Configure rustls with vefas-rustls-provider
2. **Session Establishment** → Real TLS handshake via rustls
3. **Data Extraction** → Certificates, keys, handshake data via rustls APIs
4. **Guest Verification** → Same rustls APIs in zkVM with precompile optimization
5. **Proof Generation** → Structured zkVM commitment
6. **Verification** → Proof validation

### **6.3. Context7 Rule**
Always pull in RFC 8446 (TLS 1.3), rustls documentation, and platform-specific zkVM docs before implementation.

### **6.4. Git Repo Reference Rule**

Use git-mcp for official GitHub repo examples of SP1, RISC0, rustls and rustls-wolfcrypt-provider when implementing features related to those libraries:

- **SP1 Examples**: Use git-mcp-sp1 for referencing succinctlabs/sp1 repository for SP1-specific implementation patterns
- **RISC0 Examples**: Use git-mcp-risc0 for referencing risc0/risc0 repository for RISC0-specific implementation patterns
- **rustls Integration**: Use git-mcp-rustls for referencing rustls/rustls repository for TLS implementation patterns
- **Provider Patterns**: Use git-mcp-rustls-wolfcrypt-provider for referencing wolfSSL/rustls-wolfcrypt-provider for custom CryptoProvider implementation examples

Always consult official repositories through git-mcp to ensure implementation follows established patterns and best practices.

### **6.5. Production Quality Standards**

* **No mocks/stubs in production code** - All TLS operations use real rustls
* **Same APIs everywhere** - rustls consistency between host and guest
* **Rust best practices**: Idiomatic `Result<T, E>`, zero `unsafe` unless mandatory
* **Platform-specific optimizations**: Automatic precompile routing within provider
* **Comprehensive error handling**: Graceful failure modes with detailed error messages
* **Memory efficiency**: Optimize for zkVM constraints in guest programs

---

## **7. MVP Scope**

### **7.1. Supported Platforms**
* **SP1 zkVM**: rustls + vefas-rustls-sp1 with SP1 crypto libraries
* **RISC0 zkVM**: rustls + vefas-rustls-risc0 with RISC0 crypto libraries

### **7.2. TLS Protocol Support**
* **TLS 1.3 only** (RFC 8446) via rustls
* **Cipher suites**: TLS_AES_128_GCM_SHA256 with platform optimization
* **Key exchange**: ECDHE with X25519 or P-256
* **Authentication**: ECDSA, Ed25519, RSA certificate signatures

### **7.3. Input Requirements**
* **Client ephemeral key** as input (for deterministic proof generation)
* **TLS session data** captured via rustls APIs
* **Certificate chain** extracted via rustls
* **HTTP request/response** data over rustls TLS

### **7.4. Proof Output Structure**
```json
{
  "domain": "target.domain.com",
  "request_commitment": "sha256_hash_of_request",
  "response_commitment": "sha256_hash_of_response",
  "status_code": 200,
  "tls_version": "1.3",
  "cipher_suite": "TLS_AES_256_GCM_SHA384",
  "certificate_chain_hash": "sha256_hash_of_cert_chain",
  "handshake_transcript_hash": "sha256_hash_of_transcript",
  "timestamp": 1234567890,
  "execution_metadata": {
    "cycles": 1000000,
    "memory_usage": 2048,
    "execution_time_ms": 150,
    "platform": "sp1|risc0",
    "proof_time_ms": 75
  }
}
```

---

## **8. Success Criteria**

### **8.1. Core Functionality**
✅ **Single TLS stack**: rustls runs in both host (std) and guest (no_std + alloc)
✅ **Platform providers**: vefas-rustls-sp1/risc0 handle platform-specific optimizations
✅ **Proof generation**: zkProof produced using rustls session data
✅ **Cross-platform consistency**: Same provider produces equivalent proofs

### **8.2. Test Coverage**
✅ **Provider tests**: Single provider validation across all scenarios
✅ **rustls integration**: Full TLS + zkProof pipeline via rustls
✅ **Platform tests**: SP1 and RISC0 guest programs with same provider
✅ **Cross-platform tests**: Consistency validation with unified architecture

### **8.3. Production Quality**
✅ **TLS correctness**: rustls ensures RFC 8446 compliance
✅ **Performance optimization**: Automatic precompile routing within provider
✅ **Error handling**: Comprehensive rustls error propagation
✅ **Documentation**: Complete API docs for unified architecture

### **8.4. Gateway Integration**
✅ **REST API**: HTTP endpoints for rustls-based proof generation
✅ **CLI interface**: Command-line tool for rustls operations
✅ **Configuration**: Unified configuration for single provider
✅ **Monitoring**: Comprehensive logging and performance metrics

---
