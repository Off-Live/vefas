# Trusted Root CA Certificates

This directory contains trusted root CA certificates used for certificate chain validation in the RISC0 zkVM guest.

## Quick Start

To download and convert the latest root certificates:

```bash
cd crates/vefas-risc0/certs
chmod +x download_roots.sh
./download_roots.sh
```

## Current Root CAs

The following root certificates are embedded in the guest:

1. **Let's Encrypt ISRG Root X1**
   - Most widely used free certificate authority
   - Used by: Let's Encrypt certificates
   - Algorithm: RSA 4096
   - Expires: 2035

2. **DigiCert Global Root CA**
   - Major commercial certificate authority
   - Used by: Many enterprise websites
   - Algorithm: RSA 2048
   - Expires: 2031

3. **Amazon Root CA 1**
   - Amazon Web Services root
   - Used by: AWS services, Amazon properties
   - Algorithm: RSA 2048
   - Expires: 2038

4. **Google Trust Services GTS Root R1**
   - Google's certificate authority
   - Used by: Google services
   - Algorithm: RSA 4096
   - Expires: 2036

5. **Cloudflare ECC CA-3**
   - Cloudflare's ECDSA root
   - Used by: Cloudflare-protected sites
   - Algorithm: ECDSA P-256
   - Expires: 2034

## File Format

All certificates are stored in **DER format** (Distinguished Encoding Rules), which is the binary encoding of X.509 certificates.

- **PEM format**: Text-based, starts with `-----BEGIN CERTIFICATE-----`
- **DER format**: Binary, used for embedding in compiled code

## Adding New Root CAs

To add a new trusted root CA:

1. **Obtain the root certificate** in PEM format from the CA's website

2. **Convert to DER format**:
   ```bash
   openssl x509 -in root.pem -outform DER -out roots/new-root.der
   ```

3. **Add to guest code**:
   - Edit `methods/guest/src/trusted_roots.rs`
   - Add a constant with `include_bytes!`:
     ```rust
     pub const NEW_ROOT: &[u8] = include_bytes!("../../../certs/roots/new-root.der");
     ```
   - Add to `TRUSTED_ROOTS` array

4. **Rebuild the guest**:
   ```bash
   cargo build -p vefas-risc0 --release
   ```

## Verifying Certificates

To view details of a DER certificate:

```bash
openssl x509 -in roots/isrg-root-x1.der -inform DER -text -noout
```

To verify a certificate file:

```bash
openssl x509 -in roots/isrg-root-x1.der -inform DER -noout
echo $?  # Should output 0 if valid
```

## Security Considerations

### Trust Model

- These root certificates represent the **trust anchors** for the zkTLS system
- Only certificates signed by these roots (or their intermediates) will be accepted
- The security of the entire system depends on the integrity of these roots

### Maintenance

- Root certificates should be **periodically reviewed** and updated
- Expired or compromised roots should be **removed immediately**
- New widely-trusted roots should be **added as needed**

### Recommended Update Schedule

- **Quarterly**: Check for expired certificates
- **Annually**: Review and update the complete list
- **Immediately**: Remove any compromised or revoked roots

## Certificate Sources

Official sources for root certificates:

- **Let's Encrypt**: https://letsencrypt.org/certificates/
- **DigiCert**: https://www.digicert.com/kb/digicert-root-certificates.htm
- **Amazon**: https://www.amazontrust.com/repository/
- **Google**: https://pki.goog/
- **Cloudflare**: https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/

## Testing

After adding or updating certificates, test with:

```bash
# Build the guest
cargo build -p vefas-risc0 --release

# Run tests
cargo test -p vefas-risc0

# Test with real TLS connections
cargo run -p vefas-gateway --release
```

## Troubleshooting

### Certificate Not Found Error

If you see errors about missing certificate files:

```
error: couldn't read ...: No such file or directory
```

Run the download script:
```bash
./download_roots.sh
```

### Invalid Certificate Format

If certificates fail to parse:

1. Verify the file is in DER format:
   ```bash
   file roots/certificate.der
   # Should output: "data" or "Certificate"
   ```

2. Check the first byte is 0x30 (SEQUENCE tag):
   ```bash
   xxd -l 1 roots/certificate.der
   # Should show: 00000000: 30
   ```

3. Reconvert from PEM:
   ```bash
   openssl x509 -in certificate.pem -outform DER -out roots/certificate.der
   ```

## Size Considerations

Root certificates add to the guest binary size:

- Average root certificate: ~1-2 KB
- 5 roots: ~5-10 KB total
- This is acceptable overhead for security

To minimize size, only include roots for CAs you actually need to support.

## License

Root certificates are provided by their respective Certificate Authorities and are subject to their terms of use. The certificates themselves are public and freely distributable.
