# VEFAS: Verifiable Execution Framework for Agents

*A production-grade zkTLS framework for generating cryptographic proofs of HTTPS requests and responses*

## Vision & Goal

AI Agents often hallucinate external actions (e.g., claiming "Email sent" without actually sending it).
**VEFAS** eliminates this by making external requests **cryptographically verifiable**:

> At time `T`, with a given request `{method, headers, query, body}`,
> I sent it to resource `https://abc.xyz` over TLS,
> and received the response `{status, payload}`.

The proof is portable and verifiable by anyone — **no MPC, no notary, no trust in gateway**.

### Key Features

- ✅ **Selective Disclosure**: Prove individual components (request, response, domain, timestamp) independently
- ✅ **Privacy-Preserving**: Share only what you want without revealing everything
- ✅ **Zero-Knowledge Proofs**: Powered by RISC0 and SP1 zkVMs with CUDA acceleration
- ✅ **TLS 1.3 Support**: Full support for modern TLS protocol with certificate validation
- ✅ **Production Ready**: Unified node with comprehensive verification and attestation
- ✅ **Cross-Platform**: Works seamlessly across different zkVM platforms

## Quick Start

### Installation
See [SETUP.md](./SETUP.md) for complete installation instructions including Rust, SP1, and RISC0 setup.

### Usage (after setup)
```bash
# Start the unified VEFAS node server
cargo run -p vefas-node --release --features cuda

# Generate a proof (example)
curl -X POST http://127.0.0.1:8080/requests \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "method": "GET",
    "platform": "risc0"
  }'

# Verify a proof with selective disclosure
curl -X POST http://127.0.0.1:8080/verify \
  -H "Content-Type: application/json" \
  -d '{
    "proof": {
      "platform": "risc0",
      "proof_data": "base64_encoded_proof_data"
    },
    "selective_fields": ["Domain", "Timestamp"]
  }'
```

## How It Works

VEFAS uses a **unified architecture** with comprehensive verification:

### Phase 1: Capture & Validate (Host)
- Establish a real TLS 1.3 connection to the target server
- Capture the complete TLS handshake and HTTP exchange
- Validate certificate chains with bundled root certificates
- Generate cryptographic commitments for selective disclosure

### Phase 2: Prove & Verify (zkVM)
- Verify the TLS handshake and cryptographic signatures
- Validate the HTTP request and response integrity
- Generate a zero-knowledge proof of the entire session
- Support selective field verification with Merkle proofs

### Phase 3: Attestation (Optional)
- Generate Ed25519-signed attestations for certificate validation
- Support OCSP checking and Certificate Transparency verification
- Provide comprehensive audit trails

### Selective Disclosure
Users can choose what to reveal:
- **Request Only**: Prove "I sent this request" without showing the response
- **Response Only**: Prove "Server returned this" without showing the request
- **Domain + Timestamp**: Prove "I contacted example.com at time T" without showing content
- **Full Session**: Share complete request and response details

## Use Cases

### AI Agent Verification
Prove that an AI agent actually performed claimed actions:
- Email sending confirmation
- API calls to external services
- Data retrieval from authenticated endpoints

### Privacy-Preserving Authentication
Prove you accessed a service without revealing credentials:
- Prove account ownership without sharing passwords
- Verify API access without exposing API keys
- Demonstrate service usage without revealing personal data

### Audit and Compliance
Create verifiable audit trails:
- Prove regulatory API calls were made
- Verify data was retrieved from official sources
- Create tamper-proof logs of external interactions

## Project Structure

```
vefas/
├── crates/
│   ├── vefas-node/         # Unified HTTP execution and proof verification service
│   │   ├── src/zktls/      # zkTLS components (prover, verifier, attestation)
│   │   └── certs/          # Bundled root certificates
│   ├── vefas-core/         # TLS client and session management
│   ├── vefas-rustls/       # Custom TLS implementation with capture
│   ├── vefas-types/        # Platform-agnostic no_std types
│   ├── vefas-crypto/       # Cryptographic traits and shared utilities
│   ├── vefas-crypto-native/ # Native crypto implementations (aws-lc-rs)
│   ├── vefas-crypto-sp1/   # SP1 zkVM crypto implementations
│   ├── vefas-crypto-risc0/ # RISC0 zkVM crypto implementations
│   ├── vefas-sp1/          # SP1 zkVM integration (host + guest)
│   └── vefas-risc0/        # RISC0 zkVM integration (host + guest)
├── tests/                  # End-to-end integration tests
└── fixtures/               # Test certificates and TLS transcripts
```

## VEFAS Node API

The unified VEFAS Node provides REST endpoints for generating and verifying zkTLS proofs:

### Core Endpoints
- `POST /requests` - Execute HTTPS request and generate ZK proof
- `POST /verify` - Verify ZK proof with selective disclosure
- `GET /health` - Service health and available platforms
- `GET /` - Service information and API documentation

### Request Format
```json
{
  "url": "https://example.com",
  "method": "GET",
  "platform": "risc0"  // or "sp1"
}
```

### Verification Format
```json
{
  "proof": {
    "platform": "risc0",
    "proof_data": "base64_encoded_proof"
  },
  "selective_fields": ["Domain", "Timestamp", "HttpRequest"]
}
```

## Supported zkVM Platforms

- **RISC0** - Mature platform with comprehensive tooling and CUDA acceleration
- **SP1** - High-performance zkVM with optimized precompiles
- **Cross-Platform**: Seamless switching between platforms with consistent API

## TLS Protocol Support

- **TLS 1.3** (RFC 8446) with full handshake verification
- **Cipher suites**: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- **Key exchange**: ECDHE with X25519 or P-256
- **Authentication**: ECDSA, Ed25519, RSA certificates
- **Certificate validation**: Bundled root certificates with OCSP and CT support

## Architecture Components

### zkTLS Module (`vefas-node/src/zktls/`)
- **ProverService**: Handles ZK proof generation for RISC0 and SP1
- **VerifierService**: Validates ZK proofs and Merkle proofs for selective disclosure
- **CertificateValidator**: Validates certificate chains with bundled roots
- **AttestationSigner**: Generates Ed25519-signed attestations
- **OcspChecker**: Online Certificate Status Protocol verification
- **CtLogVerifier**: Certificate Transparency log verification

## Testing & Quality Assurance

### Test Structure
- **End-to-End Tests**: Comprehensive integration testing with real TLS sessions
- **Security Tests**: Fuzzing, attack vectors, and penetration testing
- **Cross-Platform Tests**: Consistency verification across RISC0 and SP1
- **Performance Tests**: Proving time and verification cost benchmarks

### Test Categories
- `tests/e2e_tests.rs` - Main E2E test orchestrator
- `tests/security/` - Security testing suite
- `crates/*/tests/` - Unit and integration tests per crate
- `fixtures/` - Test certificates and TLS transcripts

## Development

### Key Design Principles
- **no_std Compatibility**: All core types work in zkVM guest environments
- **Platform Agnostic**: Traits work across all zkVM platforms
- **Production Ready**: Comprehensive error handling and validation
- **Security First**: Constant-time operations and cryptographic best practices

### Build Features
- `cuda` - Enable CUDA acceleration for RISC0
- `sp1` - Enable SP1 zkVM support (default)
- `risc0` - Enable RISC0 zkVM support (default)

## Documentation

- [SETUP.md](./SETUP.md) - Installation and setup guide
- [CUDA_SETUP.md](./CUDA_SETUP.md) - GPU acceleration setup
- [CLAUDE.md](./CLAUDE.md) - Development guidelines and architecture details

## Contributing

See [CLAUDE.md](./CLAUDE.md) for development guidelines, architecture details, and implementation principles.

## License

Apache-2.0
