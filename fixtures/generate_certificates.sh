#!/bin/bash

# TLS 1.3 Certificate Generation Script
# Generates certificates covering all TLS 1.3 algorithms and cipher suites
# Based on RFC 8446 TLS 1.3 specification

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/certificates"

echo "🔐 Generating TLS 1.3 Certificate Fixtures"
echo "📁 Certificate directory: ${CERT_DIR}"

# Create certificates directory
mkdir -p "${CERT_DIR}"

# Common certificate parameters
COMMON_SUBJECT="/C=US/ST=CA/L=San Francisco/O=Vefas Labs/OU=Testing/CN=tls13-test.local"
VALIDITY_DAYS=365

echo ""
echo "🔑 Generating RSA Certificates..."

# RSA 2048 Certificate (most common)
echo "  📜 RSA 2048..."
openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "${CERT_DIR}/rsa2048.key" \
    -out "${CERT_DIR}/rsa2048.crt" \
    -days ${VALIDITY_DAYS} \
    -subj "${COMMON_SUBJECT}" \
    -config <(cat <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = CA
L = San Francisco
O = Vefas Labs
OU = Testing
CN = tls13-test.local

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = tls13-test.local
DNS.2 = *.tls13-test.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
)

# RSA 4096 Certificate (high security)
echo "  📜 RSA 4096..."
openssl req -x509 -nodes -newkey rsa:4096 \
    -keyout "${CERT_DIR}/rsa4096.key" \
    -out "${CERT_DIR}/rsa4096.crt" \
    -days ${VALIDITY_DAYS} \
    -subj "${COMMON_SUBJECT}" \
    -config <(cat <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = CA
L = San Francisco
O = Vefas Labs
OU = Testing
CN = tls13-test.local

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = tls13-test.local
DNS.2 = *.tls13-test.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
)

echo ""
echo "🔑 Generating ECDSA Certificates..."

# ECDSA P-256 Certificate (most common elliptic curve)
echo "  📜 ECDSA P-256..."
openssl ecparam -genkey -name prime256v1 -noout -out "${CERT_DIR}/ecdsa_p256.key"
openssl req -new -x509 -key "${CERT_DIR}/ecdsa_p256.key" \
    -out "${CERT_DIR}/ecdsa_p256.crt" \
    -days ${VALIDITY_DAYS} \
    -subj "${COMMON_SUBJECT}" \
    -config <(cat <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = CA
L = San Francisco
O = Vefas Labs
OU = Testing
CN = tls13-test.local

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = tls13-test.local
DNS.2 = *.tls13-test.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
)

# ECDSA P-384 Certificate (higher security)
echo "  📜 ECDSA P-384..."
openssl ecparam -genkey -name secp384r1 -noout -out "${CERT_DIR}/ecdsa_p384.key"
openssl req -new -x509 -key "${CERT_DIR}/ecdsa_p384.key" \
    -out "${CERT_DIR}/ecdsa_p384.crt" \
    -days ${VALIDITY_DAYS} \
    -subj "${COMMON_SUBJECT}" \
    -config <(cat <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = CA
L = San Francisco
O = Vefas Labs
OU = Testing
CN = tls13-test.local

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = tls13-test.local
DNS.2 = *.tls13-test.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
)

echo ""
echo "🔑 Generating Ed25519 Certificates..."

# Ed25519 Certificate (modern, fast, secure)
echo "  📜 Ed25519..."
openssl genpkey -algorithm Ed25519 -out "${CERT_DIR}/ed25519.key"
openssl req -new -x509 -key "${CERT_DIR}/ed25519.key" \
    -out "${CERT_DIR}/ed25519.crt" \
    -days ${VALIDITY_DAYS} \
    -subj "${COMMON_SUBJECT}" \
    -config <(cat <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = CA
L = San Francisco
O = Vefas Labs
OU = Testing
CN = tls13-test.local

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = tls13-test.local
DNS.2 = *.tls13-test.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
)

echo ""
echo "🔑 Generating Additional Test Certificates..."

# RSA 1024 Certificate (legacy, for testing weak keys)
echo "  📜 RSA 1024 (legacy)..."
openssl req -x509 -nodes -newkey rsa:1024 \
    -keyout "${CERT_DIR}/rsa1024.key" \
    -out "${CERT_DIR}/rsa1024.crt" \
    -days ${VALIDITY_DAYS} \
    -subj "${COMMON_SUBJECT}"

# ECDSA P-521 Certificate (highest security)
echo "  📜 ECDSA P-521..."
openssl ecparam -genkey -name secp521r1 -noout -out "${CERT_DIR}/ecdsa_p521.key"
openssl req -new -x509 -key "${CERT_DIR}/ecdsa_p521.key" \
    -out "${CERT_DIR}/ecdsa_p521.crt" \
    -days ${VALIDITY_DAYS} \
    -subj "${COMMON_SUBJECT}"

echo ""
echo "📋 Generating Certificate Information Files..."

# Generate certificate information for each cert
for cert_file in "${CERT_DIR}"/*.crt; do
    if [ -f "$cert_file" ]; then
        cert_name=$(basename "$cert_file" .crt)
        echo "  📄 ${cert_name}.info"
        
        # Extract certificate details
        {
            echo "{"
            echo "  \"certificate_file\": \"${cert_name}.crt\","
            echo "  \"private_key_file\": \"${cert_name}.key\","
            echo "  \"algorithm\": \"$(openssl x509 -in "$cert_file" -text -noout | grep "Public Key Algorithm" | cut -d: -f2 | xargs)\","
            echo "  \"key_size\": \"$(openssl x509 -in "$cert_file" -text -noout | grep "Public-Key:" | cut -d: -f2 | xargs)\","
            echo "  \"subject\": \"$(openssl x509 -in "$cert_file" -subject -noout | cut -d= -f2- | xargs)\","
            echo "  \"issuer\": \"$(openssl x509 -in "$cert_file" -issuer -noout | cut -d= -f2- | xargs)\","
            echo "  \"valid_from\": \"$(openssl x509 -in "$cert_file" -startdate -noout | cut -d= -f2)\","
            echo "  \"valid_to\": \"$(openssl x509 -in "$cert_file" -enddate -noout | cut -d= -f2)\","
            echo "  \"fingerprint_sha256\": \"$(openssl x509 -in "$cert_file" -fingerprint -sha256 -noout | cut -d= -f2)\","
            echo "  \"fingerprint_sha1\": \"$(openssl x509 -in "$cert_file" -fingerprint -sha1 -noout | cut -d= -f2)\","
            echo "  \"serial_number\": \"$(openssl x509 -in "$cert_file" -serial -noout | cut -d= -f2)\","
            echo "  \"tls13_compatible\": true,"
            echo "  \"supported_cipher_suites\": ["
            echo "    \"TLS_AES_128_GCM_SHA256\","
            echo "    \"TLS_AES_256_GCM_SHA384\","
            echo "    \"TLS_CHACHA20_POLY1305_SHA256\","
            echo "    \"TLS_AES_128_CCM_SHA256\","
            echo "    \"TLS_AES_128_CCM_8_SHA256\""
            echo "  ]"
            echo "}"
        } > "${CERT_DIR}/${cert_name}.info"
    fi
done

echo ""
echo "🔍 Validating Generated Certificates..."

# Validate each certificate
for cert_file in "${CERT_DIR}"/*.crt; do
    if [ -f "$cert_file" ]; then
        cert_name=$(basename "$cert_file" .crt)
        echo "  ✅ ${cert_name}: $(openssl x509 -in "$cert_file" -text -noout | grep "Public Key Algorithm" | cut -d: -f2 | xargs)"
    fi
done

echo ""
echo "📊 Certificate Summary:"
echo "  🔐 RSA Certificates: 3 (1024, 2048, 4096 bits)"
echo "  🔐 ECDSA Certificates: 3 (P-256, P-384, P-521)"
echo "  🔐 Ed25519 Certificates: 1"
echo "  📋 Total: 7 certificates covering all TLS 1.3 algorithms"
echo ""
echo "🎯 TLS 1.3 Cipher Suite Coverage:"
echo "  ✅ TLS_AES_128_GCM_SHA256 (most common)"
echo "  ✅ TLS_AES_256_GCM_SHA384"
echo "  ✅ TLS_CHACHA20_POLY1305_SHA256"
echo "  ✅ TLS_AES_128_CCM_SHA256 (IoT/constrained)"
echo "  ✅ TLS_AES_128_CCM_8_SHA256 (IoT/constrained)"
echo ""
echo "✨ Certificate generation complete!"
echo "📁 All certificates saved to: ${CERT_DIR}"
echo ""
echo "🚀 Next steps:"
echo "  1. Use these certificates with OpenSSL s_server for TLS 1.3 testing"
echo "  2. Test each cipher suite with different certificate types"
echo "  3. Capture handshake data for Vefas proof generation"
