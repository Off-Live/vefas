use vefas_core::VefasClient;
use vefas_types::VefasCanonicalBundle;

fn should_skip() -> bool {
    std::env::var("SKIP_NETWORK_TESTS").is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_request_tls13_smoke_test() {
    if should_skip() {
        return;
    }

    let client = VefasClient::new().expect("client");
    let (bundle, _http_data) = client
        .execute_request("GET", "https://example.com/", None, None)
        .await
        .expect("bundle");

    // Production-grade assertions that are robust across runs
    assert_eq!(bundle.domain, "example.com");
    assert_eq!(bundle.expected_status, 200);
    assert!(!bundle.client_hello().unwrap().is_empty());
    assert!(!bundle.server_hello().unwrap().is_empty());
    assert!(!bundle.encrypted_request().unwrap().is_empty());
    assert!(!bundle.encrypted_response().unwrap().is_empty());
    assert!(bundle.is_tls13_session());
}

// Omit POST determinism test in production: many servers include dynamic headers.
