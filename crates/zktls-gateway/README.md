# zkTLS Gateway

A production-grade unified API and CLI gateway for zkTLS verification across multiple zkVM platforms (SP1, RISC0).

## Features

- **Unified Interface**: Single gateway for both HTTP API and CLI operations
- **Multi-Platform Support**: SP1 and RISC0 zkVM backends
- **Production Ready**: Comprehensive logging, error handling, and monitoring
- **REST API**: HTTP/HTTPS endpoints for programmatic access
- **CLI Interface**: Command-line tool for interactive operations
- **Unified Configuration**: Single config system for both interfaces
- **Health Monitoring**: Built-in health checks and status endpoints

## Architecture

The gateway follows a clean architecture pattern:

```
┌─────────────────┐    ┌─────────────────┐
│   HTTP API      │    │   CLI Interface │
│   (REST)        │    │   (Commands)    │
└─────────┬───────┘    └─────────┬───────┘
          │                      │
          └──────────┬───────────┘
                     │
          ┌──────────▼───────────┐
          │   Gateway Service    │
          │   (Business Logic)   │
          └──────────┬───────────┘
                     │
          ┌──────────▼───────────┐
          │   Platform Layer    │
          │   (SP1, RISC0)      │
          └─────────────────────┘
```

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/vefas/vefas.git
cd vefas

# Build the gateway
cargo build --package zktls-gateway --release

# Install the CLI
cargo install --path crates/zktls-gateway
```

### Configuration

Create a configuration file:

```bash
zktls config init
```

This creates `zktls.toml` with default settings:

```toml
[server]
host = "0.0.0.0"
port = 8080
default_platform = "risc0"
request_timeout_ms = 30000
max_request_size_bytes = 10485760

[platforms.risc0]
timeout_ms = 30000
memory_limit_bytes = 1048576

[platforms.sp1]
timeout_ms = 30000
memory_limit_bytes = 2097152

[logging]
level = "info"
structured = true

[security]
enable_cors = true
allowed_origins = ["*"]
enable_rate_limiting = true
rate_limit_per_minute = 100
```

### CLI Usage

#### Generate Proof

```bash
# Generate proof using RISC0
zktls prove --platform risc0 --input data.json --output proof.bin

# Generate proof using SP1
zktls prove --platform sp1 --input data.json --output proof.bin
```

#### Verify Proof

```bash
# Verify proof
zktls verify --platform risc0 --proof proof.bin

# Verify with expected result
zktls verify --platform risc0 --proof proof.bin --expected expected.json
```

#### Start API Server

```bash
# Start server on default port
zktls server

# Start server on custom port
zktls server --port 9090 --platform risc0
```

#### Configuration Management

```bash
# Show current configuration
zktls config show

# Set configuration values
zktls config set server.port 9090
zktls config set platforms.risc0.timeout_ms 60000
zktls config set logging.level debug

# Initialize default configuration
zktls config init
```

#### Status and Health

```bash
# Show gateway status
zktls status

# Check health
curl http://localhost:8080/health
```

### API Usage

#### Start API Server

```bash
zktls server --port 8080 --platform risc0
```

#### API Endpoints

**Health Check**
```bash
GET /health
```

Response:
```json
{
  "status": "healthy",
  "platforms": {
    "risc0": "healthy",
    "sp1": "healthy"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

**Gateway Status**
```bash
GET /status
```

Response:
```json
{
  "version": "0.1.0",
  "available_platforms": ["risc0", "sp1"],
  "default_platform": "risc0",
  "uptime_seconds": 3600,
  "proofs_generated": 42,
  "proofs_verified": 38,
  "last_proof_at": "2024-01-01T00:00:00Z"
}
```

**Available Platforms**
```bash
GET /api/v1/platforms
```

Response:
```json
["risc0", "sp1"]
```

**Generate Proof**
```bash
POST /api/v1/prove
Content-Type: application/json

{
  "platform": "risc0",
  "input": {
    "domain": "example.com",
    "timestamp": 1700000000,
    "handshake_transcript": "1603010040...",
    "certificates": ["308201a8..."],
    "http_request": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "http_response": "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Hello</html>"
  },
  "timeout_ms": 30000
}
```

Response:
```json
{
  "proof": "base64_encoded_proof_data",
  "metadata": {
    "platform": "risc0",
    "generated_at": "2024-01-01T00:00:00Z",
    "size_bytes": 1024,
    "generation_time_ms": 5000,
    "cycles": 800000,
    "memory_usage_bytes": 1048576
  },
  "request_id": "uuid-request-id"
}
```

**Verify Proof**
```bash
POST /api/v1/verify
Content-Type: application/json

{
  "platform": "risc0",
  "proof": "base64_encoded_proof_data",
  "expected": {
    "domain": "example.com",
    "status_code": 200,
    "tls_version": "TLS1_3",
    "cipher_suite": "Aes128GcmSha256"
  }
}
```

Response:
```json
{
  "verified": true,
  "claim": {
    "domain": "example.com",
    "status_code": 200,
    "tls_version": "TLS1_3",
    "cipher_suite": "Aes128GcmSha256",
    "certificate_chain_hash": "sha256_hash",
    "handshake_transcript_hash": "sha256_hash",
    "timestamp": 1700000000,
    "execution_metadata": {
      "cycles": 800000,
      "memory_usage": 1048576,
      "execution_time_ms": 5000,
      "platform": "risc0",
      "proof_time_ms": 2000
    }
  },
  "request_id": "uuid-request-id"
}
```

## Input Format

The gateway expects input in the following format:

```json
{
  "domain": "example.com",
  "timestamp": 1700000000,
  "handshake_transcript": "hex_encoded_tls_handshake",
  "certificates": ["hex_encoded_cert1", "hex_encoded_cert2"],
  "http_request": "raw_http_request_bytes",
  "http_response": "raw_http_response_bytes"
}
```

### Field Descriptions

- **domain**: The target domain name (e.g., "example.com")
- **timestamp**: Unix timestamp of the TLS session
- **handshake_transcript**: Complete TLS handshake transcript in hex format
- **certificates**: Array of X.509 certificates in DER format (hex encoded)
- **http_request**: Raw HTTP request bytes
- **http_response**: Raw HTTP response bytes

## Error Handling

The gateway provides comprehensive error handling with detailed error messages:

### Error Types

- **CONFIG_ERROR**: Configuration-related errors
- **PLATFORM_ERROR**: Platform-specific errors
- **PROOF_GENERATION_ERROR**: Proof generation failures
- **PROOF_VERIFICATION_ERROR**: Proof verification failures
- **INPUT_VALIDATION_ERROR**: Input validation failures
- **FILE_IO_ERROR**: File I/O errors
- **SERIALIZATION_ERROR**: Serialization/deserialization errors
- **HTTP_SERVER_ERROR**: HTTP server errors
- **NETWORK_ERROR**: Network-related errors
- **TIMEOUT_ERROR**: Operation timeouts
- **RESOURCE_LIMIT_ERROR**: Resource limit exceeded
- **AUTHENTICATION_ERROR**: Authentication failures
- **RATE_LIMIT_ERROR**: Rate limiting
- **INTERNAL_ERROR**: Internal server errors

### Error Response Format

```json
{
  "code": "ERROR_CODE",
  "message": "Human readable error message",
  "request_id": "uuid-request-id",
  "details": {
    "additional": "error details"
  }
}
```

## Configuration Reference

### Server Configuration

```toml
[server]
host = "0.0.0.0"                    # Server host address
port = 8080                          # Server port
default_platform = "risc0"          # Default zkVM platform
request_timeout_ms = 30000           # Request timeout in milliseconds
max_request_size_bytes = 10485760    # Maximum request size in bytes
```

### Platform Configuration

```toml
[platforms.risc0]
timeout_ms = 30000                   # Platform-specific timeout
memory_limit_bytes = 1048576         # Memory limit in bytes
options = {}                         # Platform-specific options

[platforms.sp1]
timeout_ms = 30000
memory_limit_bytes = 2097152
options = {}
```

### Logging Configuration

```toml
[logging]
level = "info"                       # Log level (trace, debug, info, warn, error)
structured = true                    # Enable structured logging
file = "/var/log/zktls.log"          # Log file path (optional)
```

### Security Configuration

```toml
[security]
enable_cors = true                   # Enable CORS
allowed_origins = ["*"]              # Allowed CORS origins
enable_rate_limiting = true          # Enable rate limiting
rate_limit_per_minute = 100          # Rate limit per minute
```

## Development

### Building

```bash
# Build all crates
cargo build --workspace

# Build gateway only
cargo build --package zktls-gateway

# Build with specific features
cargo build --package zktls-gateway --features risc0
```

### Testing

```bash
# Run all tests
cargo test --workspace

# Run gateway tests
cargo test --package zktls-gateway

# Run integration tests
cargo test --package zktls-gateway --test integration_tests
```

### Linting

```bash
# Format code
cargo fmt --all

# Lint code
cargo clippy --all-targets --all-features -- -D warnings
```

## Production Deployment

### Docker

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --package zktls-gateway --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/zktls /usr/local/bin/
EXPOSE 8080
CMD ["zktls", "server", "--port", "8080"]
```

### Systemd Service

```ini
[Unit]
Description=zkTLS Gateway
After=network.target

[Service]
Type=simple
User=zktls
Group=zktls
WorkingDirectory=/opt/zktls
ExecStart=/usr/local/bin/zktls server --port 8080
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Environment Variables

```bash
# Configuration file path
export ZKTL_CONFIG_FILE=/etc/zktls/config.toml

# Log level
export RUST_LOG=zktls_gateway=info

# Server settings
export ZKTL_HOST=0.0.0.0
export ZKTL_PORT=8080
export ZKTL_DEFAULT_PLATFORM=risc0
```

## Monitoring

### Health Checks

The gateway provides health check endpoints for monitoring:

```bash
# Basic health check
curl http://localhost:8080/health

# Detailed status
curl http://localhost:8080/status
```

### Metrics

The gateway tracks the following metrics:

- **proofs_generated**: Total number of proofs generated
- **proofs_verified**: Total number of proofs verified
- **uptime_seconds**: Server uptime in seconds
- **last_proof_at**: Timestamp of last proof generation

### Logging

The gateway uses structured logging with the following fields:

- **request_id**: Unique request identifier
- **platform**: Target zkVM platform
- **operation**: Operation type (prove, verify, health, status)
- **duration_ms**: Operation duration in milliseconds
- **status**: Operation status (success, error)
- **error**: Error details (if applicable)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## Support

For support and questions:

- **Issues**: [GitHub Issues](https://github.com/vefas/vefas/issues)
- **Discussions**: [GitHub Discussions](https://github.com/vefas/vefas/discussions)
- **Documentation**: [Project Wiki](https://github.com/vefas/vefas/wiki)
