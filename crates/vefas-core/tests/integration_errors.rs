use vefas_core::VefasClient;

fn should_skip() -> bool {
    std::env::var("SKIP_NETWORK_TESTS").is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_url_is_error() {
    let client = VefasClient::new().expect("client");
    let res = client.execute_request("GET", "not-a-url", None, None).await;
    assert!(res.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_failure_is_error() {
    if should_skip() {
        return;
    }
    // expired certificate should fail
    let client = VefasClient::new().expect("client");
    let res = client
        .execute_request("GET", "https://expired.badssl.com/", None, None)
        .await;
    assert!(res.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_timeout_is_error() {
    if should_skip() {
        return;
    }
    // unroutable IP; wrap in a short timeout to ensure test returns promptly
    let client = VefasClient::new().expect("client");
    let fut = client.execute_request("GET", "https://10.255.255.1/", None, None);
    let res = tokio::time::timeout(std::time::Duration::from_millis(200), fut).await;
    assert!(res.is_err() || res.unwrap().is_err());
}
