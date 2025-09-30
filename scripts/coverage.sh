#!/bin/bash
set -euo pipefail

# VEFAS Code Coverage Collection Script
# This script sets up the environment and runs grcov to collect code coverage
# for the entire VEFAS workspace including zkVM components

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COVERAGE_DIR="${PROJECT_ROOT}/target/coverage"

echo -e "${BLUE}🦀 VEFAS Code Coverage Collection${NC}"
echo "================================================"

# Function to print status
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}🧹 Cleaning up...${NC}"
    # Remove any existing profraw files
    find "${PROJECT_ROOT}" -name "*.profraw" -delete 2>/dev/null || true
    print_status "Cleanup completed"
}

# Set trap for cleanup on exit
trap cleanup EXIT

# Verify grcov is installed
if ! command -v grcov &> /dev/null; then
    print_error "grcov is not installed. Please run: cargo install grcov"
    exit 1
fi

print_status "grcov found: $(grcov --version)"

# Verify llvm-tools-preview is installed
if ! rustup component list --installed | grep -q "llvm-tools"; then
    print_error "llvm-tools-preview is not installed. Please run: rustup component add llvm-tools-preview"
    exit 1
fi

print_status "llvm-tools-preview is installed"

# Create coverage output directory
mkdir -p "${COVERAGE_DIR}"
print_status "Coverage directory created: ${COVERAGE_DIR}"

# Set up environment variables for coverage collection
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Cinstrument-coverage"
export RUSTDOCFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="${COVERAGE_DIR}/%p-%m.profraw"

print_status "Environment variables configured"
echo "  CARGO_INCREMENTAL: ${CARGO_INCREMENTAL}"
echo "  RUSTFLAGS: ${RUSTFLAGS}"
echo "  LLVM_PROFILE_FILE: ${LLVM_PROFILE_FILE}"

# Change to project root
cd "${PROJECT_ROOT}"

# Clean previous build artifacts
echo -e "\n${BLUE}🧼 Cleaning previous builds...${NC}"
cargo clean
print_status "Previous builds cleaned"

# Build all workspace members for coverage
echo -e "\n${BLUE}🔨 Building workspace with coverage instrumentation...${NC}"

# Note: We need to handle zkVM guest programs differently as they may not support coverage instrumentation
# For now, we'll focus on the host-side code and shared utilities

# List of crates to build and test (excluding zkVM guest programs that may not support coverage)
COVERAGE_CRATES=(
    "vefas-types"
    "vefas-crypto"
    "vefas-crypto-native"
    "vefas-crypto-sp1"
    "vefas-crypto-risc0"
    "vefas-core"
    "vefas-gateway"
    "vefas-rustls"
    "vefas-sp1"
    "vefas-risc0"
)

# Build each crate individually to ensure coverage instrumentation
for crate in "${COVERAGE_CRATES[@]}"; do
    echo -e "\n${YELLOW}Building ${crate}...${NC}"
    if cargo build --package "${crate}" --all-features; then
        print_status "Built ${crate}"
    else
        print_warning "Failed to build ${crate} with coverage - trying without coverage"
        # Fallback without coverage for problematic crates
        RUSTFLAGS="" cargo build --package "${crate}" --all-features || print_error "Failed to build ${crate}"
    fi
done

# Run tests with coverage collection
echo -e "\n${BLUE}🧪 Running tests with coverage collection...${NC}"

# Run tests for each crate that supports coverage
for crate in "${COVERAGE_CRATES[@]}"; do
    echo -e "\n${YELLOW}Testing ${crate}...${NC}"
    if cargo test --package "${crate}" --all-features; then
        print_status "Tested ${crate}"
    else
        print_warning "Some tests failed for ${crate}"
    fi
done

# Also run workspace-level tests
echo -e "\n${YELLOW}Running workspace-level tests...${NC}"
cargo test --workspace --exclude vefas-sp1-program --exclude vefas-risc0-methods-guest || print_warning "Some workspace tests failed"

# Count profraw files generated
PROFRAW_COUNT=$(find "${PROJECT_ROOT}" -name "*.profraw" | wc -l)
print_status "Generated ${PROFRAW_COUNT} profraw files"

if [ "${PROFRAW_COUNT}" -eq 0 ]; then
    print_error "No profraw files generated. Coverage collection may have failed."
    exit 1
fi

# Run grcov to generate coverage report
echo -e "\n${BLUE}📊 Generating coverage report...${NC}"

# Generate lcov report
grcov . \
    --output-config-file "${PROJECT_ROOT}/.github/actions-rs/grcov.yml" \
    --binary-path "${PROJECT_ROOT}/target/debug/deps/" \
    --source-dir "${PROJECT_ROOT}" \
    --output-path "${COVERAGE_DIR}/lcov.info"

print_status "LCOV report generated: ${COVERAGE_DIR}/lcov.info"

# Generate HTML report if genhtml is available
if command -v genhtml &> /dev/null; then
    echo -e "\n${BLUE}🌐 Generating HTML coverage report...${NC}"
    genhtml "${COVERAGE_DIR}/lcov.info" \
        --output-directory "${COVERAGE_DIR}/html" \
        --title "VEFAS Code Coverage" \
        --legend \
        --show-details \
        --branch-coverage
    print_status "HTML report generated: ${COVERAGE_DIR}/html/index.html"
else
    print_warning "genhtml not found. Install lcov for HTML reports: brew install lcov (macOS) or apt-get install lcov (Ubuntu)"
fi

# Generate summary report
echo -e "\n${BLUE}📈 Generating summary report...${NC}"
grcov . \
    --binary-path "${PROJECT_ROOT}/target/debug/deps/" \
    --source-dir "${PROJECT_ROOT}" \
    --output-type summary \
    --branch \
    --ignore-not-existing \
    --ignore '../*' \
    --ignore '/*' \
    --excl-line 'GRCOV_EXCL_LINE|unreachable!|panic!' > "${COVERAGE_DIR}/summary.txt"

# Display summary
echo -e "\n${GREEN}📋 Coverage Summary:${NC}"
cat "${COVERAGE_DIR}/summary.txt"

# Generate per-crate coverage reports
echo -e "\n${BLUE}📦 Generating per-crate coverage reports...${NC}"
mkdir -p "${COVERAGE_DIR}/per-crate"

for crate in "${COVERAGE_CRATES[@]}"; do
    echo -e "\n${YELLOW}Generating coverage for ${crate}...${NC}"

    # Find the crate directory
    CRATE_DIR="${PROJECT_ROOT}/crates/${crate}"
    if [ -d "${CRATE_DIR}" ]; then
        grcov . \
            --binary-path "${PROJECT_ROOT}/target/debug/deps/" \
            --source-dir "${CRATE_DIR}" \
            --output-type summary \
            --branch \
            --ignore-not-existing \
            --ignore '../*' \
            --ignore '/*' \
            --excl-line 'GRCOV_EXCL_LINE|unreachable!|panic!' > "${COVERAGE_DIR}/per-crate/${crate}-summary.txt" 2>/dev/null || print_warning "Could not generate coverage for ${crate}"

        if [ -f "${COVERAGE_DIR}/per-crate/${crate}-summary.txt" ]; then
            echo "  $(cat "${COVERAGE_DIR}/per-crate/${crate}-summary.txt")"
        fi
    fi
done

# Final status
echo -e "\n${GREEN}🎉 Coverage collection completed!${NC}"
echo "================================================"
echo "📁 Coverage files:"
echo "  📊 LCOV report: ${COVERAGE_DIR}/lcov.info"
echo "  📝 Summary: ${COVERAGE_DIR}/summary.txt"
echo "  📦 Per-crate: ${COVERAGE_DIR}/per-crate/"
if [ -d "${COVERAGE_DIR}/html" ]; then
    echo "  🌐 HTML report: ${COVERAGE_DIR}/html/index.html"
fi

echo -e "\n${BLUE}💡 Next steps:${NC}"
echo "1. Review the coverage summary above"
echo "2. Open HTML report in browser for detailed analysis"
echo "3. Identify uncovered code paths in per-crate reports"
echo "4. Add tests for critical uncovered code"

exit 0