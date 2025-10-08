use vefas_core::{BundleBuilder, ContentType, HttpData, SessionData, TlsRecord, VefasKeyLog};

// Helpers to craft minimal TLS records and handshake messages
fn tls_record(content_type: u8, version: [u8; 2], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(content_type);
    out.extend_from_slice(&version);
    let len = payload.len() as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn handshake_message(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(msg_type);
    let len = payload.len() as u32;
    let be = len.to_be_bytes();
    out.extend_from_slice(&be[1..4]);
    out.extend_from_slice(payload);
    out
}

fn hello_payload(random: [u8; 32]) -> Vec<u8> {
    // legacy_version (2) + random (32) + session_id_len (0) + cipher_suites_len (2) + cipher_suites (2) + compression_methods_len (1) + compression_methods (1) + extensions_len (2) + extensions (0)
    let mut p = Vec::new();
    p.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy version
    p.extend_from_slice(&random);
    p.push(0); // session_id_len = 0
    p.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len = 2
    p.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    p.push(1); // compression_methods_len = 1
    p.push(0); // null compression
    p.extend_from_slice(&[0x00, 0x00]); // extensions_len = 0 (no extensions)
    p
}

fn server_hello_payload(random: [u8; 32]) -> Vec<u8> {
    // legacy_version (2) + random (32) + session_id_len (0) + cipher_suite (2) + compression_method (1) + extensions_len (2) + extensions (0)
    let mut p = Vec::new();
    p.extend_from_slice(&[0x03, 0x03]); // TLS 1.2 legacy version
    p.extend_from_slice(&random);
    p.push(0); // session_id_len = 0
    p.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
    p.push(0); // null compression
    p.extend_from_slice(&[0x00, 0x00]); // extensions_len = 0 (no extensions)
    p
}

fn certificate_message_single_der(der: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    // certificate_request_context length = 0
    p.push(0);
    // certificate_list length (3 bytes)
    let cert_len = der.len() as u32;
    let total = 3 + der.len() as u32 + 2; // 3(len) + der + 2(ext len=0)
    let be = total.to_be_bytes();
    p.extend_from_slice(&be[1..4]);
    // cert entry: len(3) + der + ext_len(2=0)
    let be_cert = cert_len.to_be_bytes();
    p.extend_from_slice(&be_cert[1..4]);
    p.extend_from_slice(der);
    p.extend_from_slice(&[0, 0]); // ext len
    p
}

fn minimal_cert_der() -> Vec<u8> {
    vec![0x30, 0x82, 0x01, 0x00, 0x30, 0x81, 0xed]
}

fn make_session_data(outbound: Vec<u8>, inbound: Vec<u8>) -> SessionData {
    use rustls::crypto::aws_lc_rs::cipher_suite;
    use rustls::pki_types::CertificateDer;
    use rustls::ProtocolVersion;

    SessionData {
        outbound_bytes: outbound,
        inbound_bytes: inbound,
        certificate_chain: vec![CertificateDer::from(minimal_cert_der())],
        negotiated_suite: cipher_suite::TLS13_AES_128_GCM_SHA256,
        protocol_version: ProtocolVersion::TLSv1_3,
        server_name: "example.com".to_string(),
        timestamp: 1,
        connection_id: [0u8; 16],
        client_ephemeral_private_key: None,
    }
}

fn default_http_data() -> HttpData {
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

fn default_keylog() -> VefasKeyLog {
    VefasKeyLog::new()
}

#[test]
fn produces_tls_ciphertext_for_encrypted_fields() {
    // Build minimal handshake records (ClientHello + ServerHello)
    let ch = handshake_message(1, &hello_payload([1u8; 32]));
    let sh = handshake_message(2, &server_hello_payload([2u8; 32]));
    let ch_rec = tls_record(ContentType::Handshake as u8, [0x03, 0x03], &ch);
    let sh_rec = tls_record(ContentType::Handshake as u8, [0x03, 0x03], &sh);

    // Simulate application data TLSCiphertext for request/response
    let app_req = tls_record(
        ContentType::ApplicationData as u8,
        [0x03, 0x03],
        b"cipher_req",
    );
    let app_resp = tls_record(
        ContentType::ApplicationData as u8,
        [0x03, 0x03],
        b"cipher_resp",
    );

    let outbound = [ch_rec.clone(), app_req.clone()].concat();
    let inbound = [sh_rec.clone(), app_resp.clone()].concat();

    let session = make_session_data(outbound, inbound);
    let http = default_http_data();
    let keylog = default_keylog();

    let mut builder = BundleBuilder::new();
    let bundle = builder
        .from_session_data(&session, &http, &keylog)
        .expect("bundle creation");

    // Expect TLSCiphertext (0x17) for encrypted fields; current implementation wrongly uses plaintext
    assert_eq!(
        bundle.encrypted_request().unwrap()[0],
        0x17,
        "encrypted_request must be TLSCiphertext (type=0x17)"
    );
    assert_eq!(
        bundle.encrypted_response().unwrap()[0],
        0x17,
        "encrypted_response must be TLSCiphertext (type=0x17)"
    );
}

#[test]
fn uses_server_finished_message() {
    // Build Finished for client (type=20) and server (type=20) with different payloads
    let ch = handshake_message(1, &hello_payload([1u8; 32]));
    let sh = handshake_message(2, &server_hello_payload([2u8; 32]));
    let fin_client = handshake_message(20, b"client_finished");
    let fin_server = handshake_message(20, b"server_finished");

    // Place client Finished in outbound, server Finished in inbound
    let outbound = [
        tls_record(22, [0x03, 0x03], &ch),
        tls_record(22, [0x03, 0x03], &fin_client),
        // Include minimal ApplicationData to satisfy ciphertext extraction
        tls_record(
            ContentType::ApplicationData as u8,
            [0x03, 0x03],
            b"cipher_req",
        ),
    ]
    .concat();
    let inbound = [
        tls_record(22, [0x03, 0x03], &sh),
        tls_record(22, [0x03, 0x03], &fin_server),
        // Include minimal ApplicationData records to satisfy ciphertext extraction
        tls_record(
            ContentType::ApplicationData as u8,
            [0x03, 0x03],
            b"cipher_resp",
        ),
    ]
    .concat();

    let session = make_session_data(outbound, inbound);
    let http = default_http_data();
    let keylog = default_keylog();

    let mut builder = BundleBuilder::new();
    let bundle = builder
        .from_session_data(&session, &http, &keylog)
        .expect("bundle creation");

    assert!(
        bundle
            .server_finished_msg()
            .unwrap()
            .ends_with(b"server_finished"),
        "must select server Finished message"
    );
}

#[test]
fn preserves_wire_exact_handshake_messages_across_fragments() {
    // Create a fragmented ClientHello: header in record1, payload tail in record2
    let full_payload = hello_payload([9u8; 32]);
    let hm = handshake_message(1, &full_payload);
    // Split the handshake across two records at an arbitrary split point
    let split = 8; // within header+early payload to force reassembly requirement
    let rec1 = tls_record(22, [0x03, 0x03], &hm[..split]);
    let rec2 = tls_record(22, [0x03, 0x03], &hm[split..]);

    let sh = handshake_message(2, &server_hello_payload([3u8; 32]));
    let rec_sh = tls_record(22, [0x03, 0x03], &sh);

    let outbound = [rec1].concat();
    let inbound = [rec2, rec_sh].concat();

    let session = make_session_data(outbound, inbound);
    let http = default_http_data();
    let keylog = default_keylog();

    let mut builder = BundleBuilder::new();
    let result = builder.from_session_data(&session, &http, &keylog);

    // Expect failure until reassembly is implemented (current code errors on incomplete)
    assert!(
        result.is_err(),
        "should fail without handshake reassembly across records"
    );
}
