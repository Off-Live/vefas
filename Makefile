# VEFAS zkTLS Build Automation
# Production-grade build system following TDD methodology

.PHONY: all test test-unit test-integration test-guest test-performance clean build-sp1 build-risc0 build-gateway help

# Default target
all: test

# Run all tests following TDD methodology
test:
	@echo "🧪 Running VEFAS zkTLS Test Suite..."
	cargo test --workspace --verbose

# Unit tests for individual components
test-unit:
	@echo "🔬 Running unit tests..."
	cargo test --package zktls-core --package zktls-crypto --package zktls-zkvm

# Integration tests for full TLS + zkProof pipeline
test-integration:
	@echo "🔗 Running integration tests..."
	cargo test --package zktls-gateway --test integration

# Guest program tests for SP1 zkVM
test-guest:
	@echo "👻 Running guest program tests..."
	cargo test --package zktls-sp1 --package zktls-risc0 --test guest

# Performance benchmarks
test-performance:
	@echo "⚡ Running performance benchmarks..."
	cargo test --package zktls-gateway --test performance

# Platform-specific tests
test-sp1:
	@echo "🚀 Running SP1 platform tests..."
	cargo test --package zktls-sp1 --verbose

test-risc0:
	@echo "🔧 Running RISC0 platform tests..."
	cargo test --package zktls-risc0 --verbose

# Build specific platforms
build-sp1:
	@echo "🏗️  Building SP1 platform..."
	cargo build --package zktls-sp1 --release

build-risc0:
	@echo "🏗️  Building RISC0 platform..."
	cargo build --package zktls-risc0 --release

build-gateway:
	@echo "🌐 Building unified gateway..."
	cargo build --package zktls-gateway --release

# Generate proofs for testing (TDD workflow)
prove:
	@echo "🔐 Generating zkProofs for testing..."
	cargo run --package zktls-gateway -- prove --platform sp1 --input tests/fixtures/sample_input.json
	cargo run --package zktls-gateway -- prove --platform risc0 --input tests/fixtures/sample_input.json

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean

# Format code following Rust standards
fmt:
	@echo "✨ Formatting code..."
	cargo fmt --all

# Lint code for quality assurance
lint:
	@echo "🔍 Linting code..."
	cargo clippy --all-targets --all-features -- -D warnings

# Security audit
audit:
	@echo "🛡️  Running security audit..."
	cargo audit

# Documentation generation
docs:
	@echo "📚 Generating documentation..."
	cargo doc --workspace --no-deps --open

# Help
help:
	@echo "VEFAS zkTLS Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  test              - Run all tests (TDD workflow)"
	@echo "  test-unit         - Run unit tests for core components"
	@echo "  test-integration  - Run integration tests for full pipeline"
	@echo "  test-guest        - Run guest program tests"
	@echo "  test-performance - Run performance benchmarks"
	@echo "  test-sp1          - Run SP1 platform tests"
	@echo "  test-risc0        - Run RISC0 platform tests"
	@echo "  build-sp1         - Build SP1 platform"
	@echo "  build-risc0       - Build RISC0 platform"
	@echo "  build-gateway     - Build unified gateway"
	@echo "  prove             - Generate zkProofs for testing"
	@echo "  clean             - Clean build artifacts"
	@echo "  fmt               - Format code"
	@echo "  lint              - Lint code"
	@echo "  audit             - Security audit"
	@echo "  docs              - Generate documentation"
	@echo "  help              - Show this help"
