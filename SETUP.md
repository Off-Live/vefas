# VEFAS Setup Guide

This guide will walk you through setting up VEFAS (Verifiable Execution Framework for Agents) on your local machine.

## Prerequisites

### System Requirements
- **Operating System**: Linux (recommended) or macOS
- **Memory**: Minimum 8GB RAM, 16GB+ recommended for proof generation
- **Storage**: At least 10GB free space
- **CPU**: Multi-core processor recommended (proof generation is CPU-intensive)

### Required Tools

#### 1. Rust Toolchain
Install the latest stable Rust toolchain: https://www.rust-lang.org/tools/install

#### 2. Git
Ensure Git is installed

#### 3. Additional Dependencies

**Linux (Ubuntu/Debian)**:
```bash
sudo apt update
sudo apt install build-essential pkg-config libssl-dev
```

**macOS**:
```bash
# Install Xcode command line tools
xcode-select --install
```

## Platform Installation

VEFAS supports two zkVM platforms. You need to install at least one:

### SP1 zkVM Setup

SP1 is the fastest zkVM platform with excellent precompile optimization.

**Install SP1 toolchain using sp1up**: https://docs.succinct.xyz/docs/sp1/getting-started/install

### RISC0 zkVM Setup

RISC0 is a mature platform with comprehensive tooling.

**Install RISC0 toolchain**: https://dev.risczero.com/api/zkvm/install

## VEFAS Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Off-Live/vefas.git
cd vefas
```

### 2. Build the Project

```bash
# Build entire workspace
cargo build --workspace

# For release build (recommended for performance)
cargo build --workspace --release
```

### 3. Run Tests to Verify Installation

```bash
# Run all tests
cargo test --workspace --verbose

# Test specific platforms
cargo test --package vefas-sp1
cargo test --package vefas-risc0
```

## Running VEFAS Gateway

### 1. Start the Gateway Server

**Development mode** (with debug logging):
```bash
# Using cargo run
cargo run --package vefas-gateway

# Or using the built binary
./target/release/vefas-gateway
```

**Production mode**:
```bash
# Build release version first
cargo build --package vefas-gateway --release

# Run with production settings
RUST_LOG=info ./target/release/vefas-gateway
```

### 2. Verify Gateway is Running

Check the health endpoint:
```bash
curl http://127.0.0.1:3000/api/v1/health
```

Expected response:
```json
{
  "status": "healthy",
  "platforms": ["sp1", "risc0"],
  "version": "0.1.0"
}
```

## Verification & Testing

### 1. Test Proof Generation

Generate a simple proof to verify everything works:

```bash
curl -X POST http://127.0.0.1:3000/api/v1/requests \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "https://api.github.com/users/octocat",
    "proof_platform": "sp1",
    "timeout_ms": 30000
  }'
```

### 2. Test Both Platforms

**SP1 Platform**:
```bash
curl -X POST http://127.0.0.1:3000/api/v1/requests \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "https://httpbin.org/json",
    "proof_platform": "sp1"
  }'
```

**RISC0 Platform**:
```bash
curl -X POST http://127.0.0.1:3000/api/v1/requests \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "https://httpbin.org/json",
    "proof_platform": "risc0"
  }'
```

## Troubleshooting

### Common Issues

1. **"cargo prove not found"**
   - Ensure SP1 toolchain is properly installed and in PATH
   - Run `sp1up` again and restart your terminal

2. **"rzup command not found"**
   - Ensure RISC0 toolchain is properly installed and in PATH
   - Run the RISC0 install script again

3. **TLS/SSL errors during proof generation**
   - Install system CA certificates:
     ```bash
     # Ubuntu/Debian
     sudo apt install ca-certificates

     # macOS
     brew install ca-certificates
     ```

4. **Out of memory during proof generation**
   - Reduce concurrent proofs in configuration
   - Increase system memory or use swap
   - Use smaller test inputs

5. **Build errors with linking**
   - Install additional system dependencies:
     ```bash
     # Ubuntu/Debian
     sudo apt install clang llvm

     # macOS
     xcode-select --install
     ```

### Performance Optimization

1. **Enable release mode** for all operations:
   ```bash
   export CARGO_PROFILE_RELEASE_DEBUG=false
   cargo build --release
   ```

2. **Tune proof generation**:
   - Use SP1 for faster proving times
   - Adjust `VEFAS_MAX_CONCURRENT_PROOFS` based on CPU cores
   - Monitor memory usage during proof generation

3. **GPU acceleration** (if available):
   - Ensure CUDA is properly installed for GPU proving
   - Configure platform-specific GPU settings

### Getting Help

- **GitHub Issues**: Report bugs and request features
- **Documentation**: Check [CLAUDE.md](./CLAUDE.md) for development guidelines
- **Community**: Join discussions in project channels

### Optional: RFC 8448 Test Vectors

For cryptographic validation, you can run RFC 8448 vector tests:

```bash
# Set environment variable pointing to your test vectors
export RFC8448_VECTORS_DIR=/path/to/your/vectors

# Run the vector tests
cargo test -p vefas-crypto --tests -- --nocapture
```

## Next Steps

Once VEFAS is installed and running:

1. **Explore the API**: Review the Gateway API documentation in the README
2. **Generate proofs**: Try different HTTP requests and proof platforms
3. **Integration**: Integrate VEFAS into your AI agent or application
4. **Development**: See [CLAUDE.md](./CLAUDE.md) for development guidelines
