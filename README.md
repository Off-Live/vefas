# VEFAS: Verifiable Execution Framework for Agents

*A zkTLS client for generating cryptographic proofs of HTTPS requests and responses*

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
- ✅ **Zero-Knowledge Proofs**: Powered by RISC0 and SP1 zkVMs
- ✅ **TLS 1.3 Support**: Full support for modern TLS protocol
- ✅ **Easy Integration**: Simple REST API for proof generation and verification

## Quick Start

### Installation
See [SETUP.md](./SETUP.md) for complete installation instructions including Rust, SP1, and RISC0 setup.

### Usage (after setup)
```bash
# Start the gateway server
cargo run --package vefas-gateway

# Generate a proof (example)
curl -X POST http://127.0.0.1:3000/api/v1/requests \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "https://example.com",
    "proof_platform": "risc0"
  }'
```

## How It Works

VEFAS uses a **two-phase architecture** to generate verifiable proofs:

### Phase 1: Capture (Host)
- Establish a real TLS 1.3 connection to the target server
- Capture the complete TLS handshake and HTTP exchange
- Generate cryptographic commitments for selective disclosure

### Phase 2: Prove (zkVM)
- Verify the TLS handshake and cryptographic signatures
- Validate the HTTP request and response integrity
- Generate a zero-knowledge proof of the entire session

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
│   ├── vefas-gateway/      # REST API server
│   ├── vefas-core/         # TLS client and session management
│   ├── vefas-rustls/       # Custom TLS implementation
│   ├── vefas-types/        # Shared data types
│   ├── vefas-crypto/       # Cryptographic primitives
│   ├── vefas-sp1/          # SP1 zkVM integration
│   └── vefas-risc0/        # RISC0 zkVM integration
└── tests/                  # Integration tests
```

## Gateway API

The VEFAS Gateway provides REST endpoints for generating and verifying zkTLS proofs:

### Core Endpoints
- `POST /api/v1/requests` - Execute HTTPS request and generate proof
- `GET /api/v1/health` - Service health and available platforms

### Example Usage

```bash
# Generate a proof
curl -X POST http://127.0.0.1:3000/api/v1/requests \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "https://api.github.com/repos/octocat/Hello-World",
    "proof_platform": "sp1"
  }'

## Supported zkVM Platforms

- **RISC0** - Mature platform with comprehensive tooling and CUDA acceleration
- **SP1** - High-performance zkVM with optimized precompiles

## TLS Protocol Support

- **TLS 1.3** (RFC 8446)
- **Cipher suites**: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- **Key exchange**: ECDHE with X25519 or P-256
- **Authentication**: ECDSA, Ed25519, RSA certificates

## Documentation

- [SETUP.md](./SETUP.md) - Installation and setup guide
- [CUDA_SETUP.md](./CUDA_SETUP.md) - GPU acceleration setup
- [CLAUDE.md](./CLAUDE.md) - Development guidelines and architecture details

## Contributing

See [CLAUDE.md](./CLAUDE.md) for development guidelines, architecture details, and implementation principles.

## License

Apache-2.0
