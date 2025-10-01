#!/bin/bash

# TLS 1.3 Server Testing Script
# Tests all certificate types with all TLS 1.3 cipher suites
# Based on RFC 8446 TLS 1.3 specification

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/certificates"
LOG_DIR="${SCRIPT_DIR}/test_logs"

echo "🚀 TLS 1.3 Comprehensive Testing Suite"
echo "📁 Certificate directory: ${CERT_DIR}"
echo "📁 Log directory: ${LOG_DIR}"

# Create log directory
mkdir -p "${LOG_DIR}"

# Function to cleanup any existing OpenSSL processes
cleanup_openssl_processes() {
    echo -e "${BLUE}🧹 Cleaning up any existing OpenSSL processes...${NC}"
    pkill -f "openssl s_server" 2>/dev/null || true
    pkill -f "openssl s_client" 2>/dev/null || true
    sleep 1
}

# Test configuration
SERVER_PORT_BASE=8443
TEST_DOMAIN="tls13-test.local"
TEST_MESSAGE="GET / HTTP/1.1\r\nHost: ${TEST_DOMAIN}\r\n\r\n"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to test a specific certificate and cipher suite combination
test_certificate_cipher() {
    local cert_name="$1"
    local cipher_suite="$2"
    local port="$3"
    local cert_file="${CERT_DIR}/${cert_name}.crt"
    local key_file="${CERT_DIR}/${cert_name}.key"
    
    echo -e "${BLUE}🔍 Testing ${cert_name} with ${cipher_suite}${NC}"
    
    # Check if port is available
    if lsof -Pi :${port} -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${YELLOW}  ⚠️  Port ${port} is in use, trying next available port${NC}"
        local original_port=$port
        while lsof -Pi :${port} -sTCP:LISTEN -t >/dev/null 2>&1; do
            port=$((port + 1))
            if [ $port -gt $((original_port + 10)) ]; then
                echo -e "${RED}  ❌ FAILED: No available ports found${NC}"
                return 3
            fi
        done
        echo -e "${BLUE}  📡 Using port ${port} instead${NC}"
    fi
    
    # Start server in background
    openssl s_server \
        -accept ${port} \
        -tls1_3 \
        -ciphersuites ${cipher_suite} \
        -cert "${cert_file}" \
        -key "${key_file}" \
        -www \
        -quiet \
        > "${LOG_DIR}/${cert_name}_${cipher_suite//[^a-zA-Z0-9]/_}.server.log" 2>&1 &
    
    local server_pid=$!
    
    # Wait for server to start and check if it's actually running
    sleep 3
    if ! kill -0 $server_pid 2>/dev/null; then
        echo -e "${RED}  ❌ FAILED: Server failed to start${NC}"
        return 3
    fi
    
    # Test client connection
    local client_log="${LOG_DIR}/${cert_name}_${cipher_suite//[^a-zA-Z0-9]/_}.client.log"
    
    echo -e "GET / HTTP/1.1\r\nHost: ${TEST_DOMAIN}\r\n\r\n" | \
        timeout 10 openssl s_client \
            -connect localhost:${port} \
            -tls1_3 \
            -ciphersuites ${cipher_suite} \
            -servername ${TEST_DOMAIN} \
            -verify_return_error \
            -verify_depth 0 \
            -CAfile "${cert_file}" \
            -quiet \
            > "${client_log}" 2>&1
    
    local client_exit_code=$?
    
    # Kill server
    kill $server_pid 2>/dev/null || true
    wait $server_pid 2>/dev/null || true
    
    # Analyze results
    if [ $client_exit_code -eq 0 ]; then
        # Check if the correct cipher was negotiated
        if grep -q "Cipher is ${cipher_suite}" "${client_log}"; then
            # Check certificate verification - accept both verified and self-signed
            if grep -q "Verify return code: 0" "${client_log}" || grep -q "Verify return code: 18" "${client_log}"; then
                echo -e "${GREEN}  ✅ SUCCESS: ${cert_name} + ${cipher_suite}${NC}"
                return 0
            else
                echo -e "${RED}  ❌ FAILED: ${cert_name} + ${cipher_suite} - Certificate verification failed${NC}"
                return 2
            fi
        else
            echo -e "${YELLOW}  ⚠️  WARNING: ${cert_name} + ${cipher_suite} - Wrong cipher negotiated${NC}"
            return 1
        fi
    else
        echo -e "${RED}  ❌ FAILED: ${cert_name} + ${cipher_suite} - Connection failed${NC}"
        return 3
    fi
}

# Function to test all cipher suites for a certificate
test_certificate_all_ciphers() {
    local cert_name="$1"
    local port_start="$2"
    local port=$port_start
    
    echo -e "\n${BLUE}🔐 Testing Certificate: ${cert_name}${NC}"
    echo "=========================================="
    
    local success_count=0
    local total_count=0
    
    # Test all TLS 1.3 cipher suites
    local cipher_suites=(
        "TLS_AES_128_GCM_SHA256"
        "TLS_AES_256_GCM_SHA384"
        "TLS_CHACHA20_POLY1305_SHA256"
        "TLS_AES_128_CCM_SHA256"
        "TLS_AES_128_CCM_8_SHA256"
    )
    
    for cipher_suite in "${cipher_suites[@]}"; do
        test_certificate_cipher "${cert_name}" "${cipher_suite}" "${port}"
        local result=$?
        
        total_count=$((total_count + 1))
        if [ $result -eq 0 ]; then
            success_count=$((success_count + 1))
        fi
        
        port=$((port + 1))
    done
    
    echo -e "${BLUE}📊 ${cert_name} Results: ${success_count}/${total_count} successful${NC}"
    return $((total_count - success_count))
}

# Function to generate test report
generate_report() {
    local report_file="${LOG_DIR}/test_report.md"
    
    echo "# TLS 1.3 Test Report" > "${report_file}"
    echo "" >> "${report_file}"
    echo "Generated: $(date)" >> "${report_file}"
    echo "" >> "${report_file}"
    echo "## Test Summary" >> "${report_file}"
    echo "" >> "${report_file}"
    
    # Count successful tests
    local total_tests=0
    local successful_tests=0
    
    for cert_name in rsa2048 rsa4096 ecdsa_p256 ecdsa_p384 ed25519; do
        if [ -f "${CERT_DIR}/${cert_name}.crt" ]; then
            echo "### ${cert_name}" >> "${report_file}"
            echo "" >> "${report_file}"
            
            for cipher_suite in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256 TLS_AES_128_CCM_SHA256 TLS_AES_128_CCM_8_SHA256; do
                local log_file="${LOG_DIR}/${cert_name}_${cipher_suite//[^a-zA-Z0-9]/_}.client.log"
                total_tests=$((total_tests + 1))
                
                if [ -f "${log_file}" ] && grep -q "Verify return code: 0" "${log_file}" && grep -q "Cipher is ${cipher_suite}" "${log_file}"; then
                    echo "- ✅ ${cipher_suite}: SUCCESS" >> "${report_file}"
                    successful_tests=$((successful_tests + 1))
                else
                    echo "- ❌ ${cipher_suite}: FAILED" >> "${report_file}"
                fi
            done
            echo "" >> "${report_file}"
        fi
    done
    
    echo "## Overall Results" >> "${report_file}"
    echo "" >> "${report_file}"
    echo "- **Total Tests**: ${total_tests}" >> "${report_file}"
    echo "- **Successful**: ${successful_tests}" >> "${report_file}"
    echo "- **Failed**: $((total_tests - successful_tests))" >> "${report_file}"
    echo "- **Success Rate**: $(( (successful_tests * 100) / total_tests ))%" >> "${report_file}"
    
    echo -e "\n${GREEN}📋 Test report generated: ${report_file}${NC}"
}

# Main testing function
run_comprehensive_tests() {
    echo -e "\n${BLUE}🧪 Starting Comprehensive TLS 1.3 Tests${NC}"
    echo "=============================================="
    
    # Cleanup any existing processes
    cleanup_openssl_processes
    
    local port=$SERVER_PORT_BASE
    local total_failures=0
    
    # Test each certificate type
    for cert_name in rsa2048 rsa4096 ecdsa_p256 ecdsa_p384 ed25519; do
        if [ -f "${CERT_DIR}/${cert_name}.crt" ]; then
            test_certificate_all_ciphers "${cert_name}" "${port}"
            total_failures=$((total_failures + $?))
            port=$((port + 10))  # Leave space between certificate tests
        else
            echo -e "${RED}❌ Certificate file not found: ${cert_name}.crt${NC}"
        fi
    done
    
    # Generate report
    generate_report
    
    # Final cleanup
    cleanup_openssl_processes
    
    echo -e "\n${BLUE}🏁 Testing Complete${NC}"
    echo "=================="
    echo -e "Total test failures: ${total_failures}"
    echo -e "Logs saved to: ${LOG_DIR}"
    
    if [ $total_failures -eq 0 ]; then
        echo -e "${GREEN}🎉 All tests passed!${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠️  Some tests failed. Check logs for details.${NC}"
        return 1
    fi
}

# Function to test specific certificate and cipher combination
test_specific_combination() {
    local cert_name="$1"
    local cipher_suite="$2"
    local port="${3:-8443}"
    
    if [ -z "$cert_name" ] || [ -z "$cipher_suite" ]; then
        echo "Usage: test_specific_combination <cert_name> <cipher_suite> [port]"
        echo "Example: test_specific_combination rsa2048 TLS_AES_128_GCM_SHA256"
        return 1
    fi
    
    echo -e "${BLUE}🎯 Testing Specific Combination${NC}"
    echo "Certificate: ${cert_name}"
    echo "Cipher Suite: ${cipher_suite}"
    echo "Port: ${port}"
    echo ""
    
    test_certificate_cipher "${cert_name}" "${cipher_suite}" "${port}"
}

# Function to show available certificates
show_certificates() {
    echo -e "${BLUE}📜 Available Certificates${NC}"
    echo "========================="
    
    for cert_file in "${CERT_DIR}"/*.crt; do
        if [ -f "$cert_file" ]; then
            local cert_name=$(basename "$cert_file" .crt)
            local algorithm=$(openssl x509 -in "$cert_file" -text -noout | grep "Public Key Algorithm" | cut -d: -f2 | xargs)
            local key_size=$(openssl x509 -in "$cert_file" -text -noout | grep "Public-Key:" | cut -d: -f2 | xargs)
            local subject=$(openssl x509 -in "$cert_file" -subject -noout | cut -d= -f2- | xargs)
            
            echo -e "${GREEN}📄 ${cert_name}${NC}"
            echo "   Algorithm: ${algorithm}"
            echo "   Key Size: ${key_size}"
            echo "   Subject: ${subject}"
            echo ""
        fi
    done
}

# Function to show available cipher suites
show_cipher_suites() {
    echo -e "${BLUE}🔐 TLS 1.3 Cipher Suites${NC}"
    echo "========================"
    
    local cipher_suites=(
        "TLS_AES_128_GCM_SHA256:Most common, AES-128-GCM with SHA256"
        "TLS_AES_256_GCM_SHA384:High security, AES-256-GCM with SHA384"
        "TLS_CHACHA20_POLY1305_SHA256:Fast encryption, ChaCha20-Poly1305 with SHA256"
        "TLS_AES_128_CCM_SHA256:IoT/constrained, AES-128-CCM with SHA256"
        "TLS_AES_128_CCM_8_SHA256:IoT/constrained, AES-128-CCM-8 with SHA256"
    )
    
    for cipher_info in "${cipher_suites[@]}"; do
        local cipher_suite="${cipher_info%%:*}"
        local description="${cipher_info##*:}"
        echo -e "${GREEN}🔐 ${cipher_suite}${NC}"
        echo "   ${description}"
        echo ""
    done
}

# Main script logic
case "${1:-all}" in
    "all")
        run_comprehensive_tests
        ;;
    "cert")
        show_certificates
        ;;
    "ciphers")
        show_cipher_suites
        ;;
    "test")
        test_specific_combination "$2" "$3" "$4"
        ;;
    "help"|"-h"|"--help")
        echo "TLS 1.3 Testing Script"
        echo ""
        echo "Usage: $0 [command] [options]"
        echo ""
        echo "Commands:"
        echo "  all                    Run comprehensive tests (default)"
        echo "  cert                   Show available certificates"
        echo "  ciphers                Show available cipher suites"
        echo "  test <cert> <cipher>   Test specific certificate and cipher combination"
        echo "  help                   Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0 all"
        echo "  $0 test rsa2048 TLS_AES_128_GCM_SHA256"
        echo "  $0 cert"
        echo "  $0 ciphers"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac
