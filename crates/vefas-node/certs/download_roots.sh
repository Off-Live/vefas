#!/bin/bash
# Download and convert trusted root CA certificates to DER format
#
# This script downloads root certificates from trusted Certificate Authorities
# and converts them to DER format for embedding in the RISC0 guest.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOTS_DIR="$SCRIPT_DIR/roots"

echo "Creating roots directory..."
mkdir -p "$ROOTS_DIR"

echo "Downloading root certificates..."

# Let's Encrypt ISRG Root X1
echo "  - Let's Encrypt ISRG Root X1"
curl -s https://letsencrypt.org/certs/isrgrootx1.pem -o "$ROOTS_DIR/isrg-root-x1.pem"
openssl x509 -in "$ROOTS_DIR/isrg-root-x1.pem" -outform DER -out "$ROOTS_DIR/isrg-root-x1.der"

# DigiCert Global Root CA
echo "  - DigiCert Global Root CA"
curl -s https://cacerts.digicert.com/DigiCertGlobalRootCA.crt.pem -o "$ROOTS_DIR/digicert-global-root-ca.pem"
openssl x509 -in "$ROOTS_DIR/digicert-global-root-ca.pem" -outform DER -out "$ROOTS_DIR/digicert-global-root-ca.der"

# Amazon Root CA 1
echo "  - Amazon Root CA 1"
curl -s https://www.amazontrust.com/repository/AmazonRootCA1.pem -o "$ROOTS_DIR/amazon-root-ca-1.pem"
openssl x509 -in "$ROOTS_DIR/amazon-root-ca-1.pem" -outform DER -out "$ROOTS_DIR/amazon-root-ca-1.der"

# Google Trust Services GTS Root R1
echo "  - Google GTS Root R1"
# Official Google Trust Services root certificate (DER format)
# From: https://pki.goog/repository/
curl -s https://i.pki.goog/r1.crt -o "$ROOTS_DIR/gts-root-r1.der"
# Verify it's a valid certificate
if ! openssl x509 -in "$ROOTS_DIR/gts-root-r1.der" -inform DER -noout 2>/dev/null; then
    echo "    Warning: Downloaded file is not a valid DER certificate"
    rm -f "$ROOTS_DIR/gts-root-r1.der"
fi

# Cloudflare Origin CA (ECC)
echo "  - Cloudflare Origin CA ECC"
# Cloudflare's origin CA certificate for ECC
# From: https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/
curl -s https://developers.cloudflare.com/ssl/static/origin_ca_ecc_root.pem -o "$ROOTS_DIR/cloudflare-ecc-ca-3.pem"
if [ -s "$ROOTS_DIR/cloudflare-ecc-ca-3.pem" ] && grep -q "BEGIN CERTIFICATE" "$ROOTS_DIR/cloudflare-ecc-ca-3.pem"; then
    openssl x509 -in "$ROOTS_DIR/cloudflare-ecc-ca-3.pem" -outform DER -out "$ROOTS_DIR/cloudflare-ecc-ca-3.der"
else
    echo "    Warning: Could not download Cloudflare ECC certificate"
    # Try RSA version as fallback
    curl -s https://developers.cloudflare.com/ssl/static/origin_ca_rsa_root.pem -o "$ROOTS_DIR/cloudflare-ecc-ca-3.pem"
    if [ -s "$ROOTS_DIR/cloudflare-ecc-ca-3.pem" ] && grep -q "BEGIN CERTIFICATE" "$ROOTS_DIR/cloudflare-ecc-ca-3.pem"; then
        openssl x509 -in "$ROOTS_DIR/cloudflare-ecc-ca-3.pem" -outform DER -out "$ROOTS_DIR/cloudflare-ecc-ca-3.der"
        echo "    Using Cloudflare RSA Origin CA instead"
    fi
fi

echo ""
echo "Root certificates downloaded and converted to DER format:"
ls -lh "$ROOTS_DIR"/*.der

echo ""
echo "Verifying certificates..."
for cert in "$ROOTS_DIR"/*.der; do
    if [ -s "$cert" ]; then
        echo "  ✓ $(basename $cert): $(stat -f%z "$cert" 2>/dev/null || stat -c%s "$cert") bytes"
        # Show certificate details
        openssl x509 -in "$cert" -inform DER -noout -subject -dates 2>/dev/null || true
    fi
done

echo ""
echo "Done! Root certificates are ready for embedding."
echo "Location: $ROOTS_DIR"
