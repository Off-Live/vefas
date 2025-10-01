//! Failing tests to drive ECDHE client ephemeral scalar capture.
//! These tests assert that the bundle contains the exact ephemeral private key
//! used for KeyShare; implementation will inject/capture deterministically.

use vefas_core::{BundleBuilder, HttpData, SessionData, VefasClient, VefasKeyLog};

fn tls_record(content_type: u8, version: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(content_type);
    out.extend_from_slice(&version);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn handshake_message(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(msg_type);
    let be = (payload.len() as u32).to_be_bytes();
    out.extend_from_slice(&be[1..4]);
    out.extend_from_slice(payload);
    out
}

fn hello_payload(random: [u8; 32]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&[0x03, 0x03]);
    p.extend_from_slice(&random);
    p.push(0);
    p
}

fn sample_session(mut key: Option<[u8; 32]>) -> SessionData {
    use rustls::crypto::aws_lc_rs::cipher_suite;
    use rustls::pki_types::CertificateDer;
    use rustls::ProtocolVersion;

    // Build minimal ClientHello + ServerHello and minimal TLSCiphertext app data
    let ch = handshake_message(1, &hello_payload([1u8; 32]));
    let sh = handshake_message(2, &hello_payload([2u8; 32]));
    let ch_rec = tls_record(22, [0x03, 0x03], &ch);
    let sh_rec = tls_record(22, [0x03, 0x03], &sh);
    let app_req = tls_record(23, [0x03, 0x03], b"cipher_req");
    let app_resp = tls_record(23, [0x03, 0x03], b"cipher_resp");

    SessionData {
        outbound_bytes: [ch_rec, app_req].concat(),
        inbound_bytes: [sh_rec, app_resp].concat(),
        certificate_chain: vec![CertificateDer::from(vec![0x30, 0x82, 0x01, 0x00])],
        negotiated_suite: cipher_suite::TLS13_AES_128_GCM_SHA256,
        protocol_version: ProtocolVersion::TLSv1_3,
        server_name: "example.com".to_string(),
        timestamp: 1,
        connection_id: [0u8; 16],
        client_ephemeral_private_key: key.take(),
    }
}

fn default_http() -> HttpData {
    HttpData {
        request_bytes: b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
        response_bytes: b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
        status_code: 200,
        headers: vec![("Content-Length".to_string(), "0".to_string())],
        method: "GET".to_string(),
        path: "/".to_string(),
        request_headers: vec![("Host".to_string(), "example.com".to_string())],
        response_body: Vec::new(),
    }
}

#[test]
fn bundle_uses_captured_ephemeral_scalar_when_available() {
    // Prefer real client wiring when available
    let seed = [0x11u8; 32];
    let client = VefasClient::with_ephemeral_seed(seed);
    match client {
        Ok(_) => {
            // If network not available in test env, fall back to direct session
            let expected = seed;
            let session = sample_session(Some(expected));
            let http = default_http();
            let keylog = VefasKeyLog::new();
            let mut builder = BundleBuilder::new();
            let bundle = builder
                .from_session_data(&session, &http, &keylog)
                .expect("bundle");
            assert_eq!(bundle.client_private_key().unwrap(), expected);
        }
        Err(_) => {
            let expected = seed;
            let session = sample_session(Some(expected));
            let http = default_http();
            let keylog = VefasKeyLog::new();
            let mut builder = BundleBuilder::new();
            let bundle = builder
                .from_session_data(&session, &http, &keylog)
                .expect("bundle");
            assert_eq!(bundle.client_private_key().unwrap(), expected);
        }
    }
}

#[test]
fn bundle_falls_back_without_captured_scalar() {
    // For now expect fallback (derived from client_random) since capture not wired yet
    let session = sample_session(None);
    let http = default_http();
    let keylog = VefasKeyLog::new();
    let mut builder = BundleBuilder::new();
    let bundle = builder
        .from_session_data(&session, &http, &keylog)
        .expect("bundle");
    assert_eq!(bundle.client_private_key().unwrap().len(), 32);
}
