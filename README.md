# VEFAS: Verifiable Execution Framework for Agents

*A revolutionary zkTLS client using host-rustls + guest-verifier architecture for optimal proof efficiency*

## Vision & Goal

AI Agents often hallucinate external actions (e.g., claiming "Email sent" without actually sending it).
**VEFAS** eliminates this by making external requests **cryptographically verifiable**:

> At time `T`, with a given request `{method, headers, query, body}`,
> I sent it to resource `https://abc.xyz` over TLS,
> and received the response `{status, payload}`.

The proof is portable and verifiable by anyone — **no MPC, no notary, no trust in gateway**.

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
    "url": "https://api.github.com/users/octocat",
    "proof_platform": "sp1"
  }'
```

## Architecture Overview

VEFAS uses a **host-guest separation** architecture that separates TLS implementation from verification:

### Host (std environment)
- **Real TLS**: Full `rustls` implementation for actual network connections
- **Bundle Capture**: Extract exact wire data (handshake, keys, encrypted records)
- **Canonical Format**: Create deterministic bundle for guest verification

### Guest (zkVM - no_std + alloc)
- **Minimal Verifier**: Purpose-built TLS verifier (~1000 lines vs ~50k rustls)
- **Direct Precompiles**: SHA256, ECDSA P-256 via SP1/RISC0 precompiles
- **Deterministic Verification**: Process canonical bundle, output proof claims

### Key Innovation
**10-100x cheaper proofs** through minimal guest verifier + direct precompile usage

## TLS Session Verification Flow

The VEFAS verification process follows these key steps:

1. **Host TLS Connection** - Establish real TLS using `rustls` and capture session data
2. **Canonical Bundle Creation** - Extract raw handshake messages, keys, and encrypted records
3. **Guest Verification** - Process bundle in zkVM using minimal verifier with precompiles
4. **Proof Generation** - Generate cryptographic proof of the verified TLS session

The resulting proof contains verifiable commitments to the request, response, and all TLS metadata.

## Crate Structure

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
│   └── vefas-risc0/             # RISC0 integration (methods, guest, host)
│
└── tests/                       # Root integration tests (spawn gateway, e2e)
```

## Gateway API

The VEFAS Gateway provides REST endpoints for generating and verifying zkTLS proofs:

### Core Endpoints
- `POST /api/v1/requests` - Execute HTTPS request and generate proof
- `POST /api/v1/verify` - Verify a proof and return verified claim
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

# Verify a proof
curl -X POST http://127.0.0.1:3000/api/v1/verify \
  -H "Content-Type: application/json" \
  -d '{"proof": {...}}'
```

## Supported Platforms

- **SP1 zkVM** - Ultra-fast proving with precompile optimization
- **RISC0 zkVM** - Mature platform with comprehensive tooling

## TLS Protocol Support

- **TLS 1.3 only** (RFC 8446) via rustls
- **Cipher suites**: TLS_AES_128_GCM_SHA256 with platform optimization
- **Key exchange**: ECDHE with X25519 or P-256
- **Authentication**: ECDSA, Ed25519, RSA certificate signatures

## Contributing

See [CLAUDE.md](./CLAUDE.md) for development guidelines, architecture details, and implementation principles.

## License

Apache-2.0
