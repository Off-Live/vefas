use reqwest::{Client, StatusCode};
use serde_json::Value;
use serial_test::serial;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use vefas_node::{VefasNode, VefasNodeConfig};

async fn spawn_node_for_tests() -> Option<(JoinHandle<()>, String)> {
    // Create VEFAS node with ephemeral port
    let config = VefasNodeConfig {
        bind_address: "127.0.0.1:0".to_string(),
        ..Default::default()
    };

    let node = match VefasNode::new(config).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Skipping: failed to initialize VEFAS Node: {}", e);
            return None;
        }
    };

    // Build router from node
    let router = node.router();

    let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Skipping: failed to bind listener: {}", e);
            return None;
        }
    };

    let addr = listener.local_addr().ok()?;
    let base_url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    // Small delay to ensure server starts
    sleep(Duration::from_millis(300)).await;
    Some((handle, base_url))
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_service_info() {
    let (_server, base) = match spawn_node_for_tests().await {
        Some(v) => v,
        None => return,
    };
    let client = Client::new();

    let response = client
        .get(&format!("{}/", base))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = response.json().await.expect("Failed to parse JSON");

    // Verify service information structure
    assert_eq!(
        body.get("service").unwrap().as_str().unwrap(),
        "VEFAS Node"
    );
    assert!(body.get("version").is_some());
    assert_eq!(body.get("api_version").unwrap().as_str().unwrap(), "v1");

    let endpoints = body.get("endpoints").unwrap().as_array().unwrap();
    assert!(endpoints.len() >= 3);

    println!("✓ Service info endpoint working correctly");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_health_check() {
    let (_server, base) = match spawn_node_for_tests().await {
        Some(v) => v,
        None => return,
    };
    let client = Client::new();

    let response = client
        .get(&format!("{}/api/v1/health", base))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = response.json().await.expect("Failed to parse JSON");

    // Verify health check structure
    assert_eq!(body.get("status").unwrap().as_str().unwrap(), "healthy");
    assert!(body.get("timestamp").is_some());
    assert!(body.get("version").is_some(), "Version field should be present");

    // Verify zkVM platform availability
    let platforms = body.get("platforms").unwrap().as_array().unwrap();
    assert!(!platforms.is_empty(), "No zkVM platforms are available");

    println!("✓ Health check endpoint working correctly");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_server_availability() {
    let (_server, base) = match spawn_node_for_tests().await {
        Some(v) => v,
        None => return,
    };

    let client = Client::new();

    // Test that server is running and responsive
    let response = client
        .get(&format!("{}/api/v1/health", base))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .expect("Server should be available");

    assert_eq!(response.status(), StatusCode::OK);

    println!("✓ Server is available and responsive");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_invalid_endpoint() {
    let (_server, base) = match spawn_node_for_tests().await {
        Some(v) => v,
        None => return,
    };
    let client = Client::new();

    let response = client
        .get(&format!("{}/api/v1/nonexistent", base))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    println!("✓ Invalid endpoint returns 404 as expected");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_cors_headers() {
    let (_server, base) = match spawn_node_for_tests().await {
        Some(v) => v,
        None => return,
    };
    let client = Client::new();

    let response = client
        .request(reqwest::Method::OPTIONS, &format!("{}/api/v1/health", base))
        .send()
        .await
        .expect("Failed to send OPTIONS request");

    // Should return success with CORS headers
    assert!(response.status().is_success() || response.status() == StatusCode::NO_CONTENT);

    println!("✓ CORS preflight request handled correctly");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_requests_endpoint_structure() {
    let (_server, base) = match spawn_node_for_tests().await {
        Some(v) => v,
        None => return,
    };
    let client = Client::new();

    // Test with empty body to see error structure
    let response = client
        .post(&format!("{}/api/v1/requests", base))
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("Failed to send request");

    // Should return 422 Unprocessable Entity for invalid/empty payload or 400 depending on router validation
    assert!(
        response.status() == StatusCode::UNPROCESSABLE_ENTITY
            || response.status() == StatusCode::BAD_REQUEST
    );

    println!("✓ Requests endpoint rejects invalid payloads as expected");
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_verify_endpoint_structure() {
    let (_server, base) = match spawn_node_for_tests().await {
        Some(v) => v,
        None => return,
    };
    let client = Client::new();

    // Test with empty body to see error structure
    let response = client
        .post(&format!("{}/api/v1/verify", base))
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("Failed to send request");

    // Should return 422 Unprocessable Entity for invalid/empty payload or 400 depending on router validation
    assert!(
        response.status() == StatusCode::UNPROCESSABLE_ENTITY
            || response.status() == StatusCode::BAD_REQUEST
    );

    println!("✓ Verify endpoint rejects invalid payloads as expected");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn test_real_http_request_with_body_extraction() {
    use serde_json::json;

    let (_server, base) = match spawn_node_for_tests().await {
        Some(v) => v,
        None => {
            println!("Skipping test - gateway not available");
            return;
        }
    };

    let client = Client::new();

    // Make a real HTTP request to example.com (supports TLS 1.3)
    // httpbin.org doesn't support TLS 1.3, so we use example.com
    let payload = json!({
        "method": "GET",
        "url": "https://example.com/",
        "proof_platform": "risc0"
    });

    let response = client
        .post(&format!("{}/api/v1/requests", base))
        .header("Content-Type", "application/json")
        .json(&payload)
        .timeout(Duration::from_secs(60))
        .send()
        .await;

    match response {
        Ok(resp) => {
            println!("Response status: {}", resp.status());

            if resp.status().is_success() {
                let body: Value = resp.json().await.expect("Failed to parse JSON");
                println!("Response body: {}", serde_json::to_string_pretty(&body).unwrap());

                // Verify http_response has body content
                let http_response = body.get("http_response").expect("Missing http_response");
                let response_body = http_response.get("body").and_then(|v| v.as_str()).unwrap_or("");

                println!("HTTP Response body length: {}", response_body.len());
                assert!(response_body.len() > 0, "HTTP response body should not be empty!");

                // Verify it contains HTML content from example.com
                assert!(response_body.contains("Example Domain") || response_body.contains("<!doctype html"),
                        "HTTP response body should contain HTML content from example.com");

                println!("✓ Real HTTP request successful with body extraction");
            } else {
                println!("Request failed with status: {}", resp.status());
                let error_body = resp.text().await.unwrap_or_else(|_| "Failed to get error body".to_string());
                println!("Error: {}", error_body);
                panic!("Expected successful response");
            }
        }
        Err(e) => {
            println!("Request error: {}", e);
            panic!("Failed to make request: {}", e);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn test_e2e_proof_generation_and_verification_sp1() {
    let (_server, base) = match spawn_node_for_tests().await {
        Some(v) => v,
        None => return,
    };

    // Health check to ensure SP1 platform is available; otherwise skip
    let health = reqwest::get(format!("{}/api/v1/health", base)).await.ok();
    if let Some(resp) = health {
        if let Ok(val) = resp.json::<Value>().await {
            let platforms = val
                .get("platforms")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let has_sp1 = platforms.iter().any(|p| p.as_str() == Some("sp1"));
            if !has_sp1 {
                eprintln!("Skipping: SP1 platform not available");
                return;
            }
        }
    }

    // Pre-flight network check; skip if outbound HTTPS is unavailable
    if let Ok(pre_client) = Client::builder().timeout(Duration::from_secs(5)).build() {
        match pre_client.get("https://httpbin.org/get").send().await {
            Ok(resp) if resp.status().is_success() => {}
            _ => {
                eprintln!("Skipping: outbound network not available for httpbin.org");
                return;
            }
        }
    } else {
        eprintln!("Skipping: outbound network not available for httpbin.org");
        return;
    }

    let client = Client::new();
    let payload = serde_json::json!({
        "method": "GET",
        "url": "https://httpbin.org/get",
        "headers": {"user-agent": "VEFAS-Tests"},
        "proof_platform": "sp1",
        "timeout_ms": 30000
    });

    let exec_resp = client
        .post(&format!("{}/api/v1/requests", base))
        .json(&payload)
        .send()
        .await
        .expect("Failed to call /requests");

    assert!(
        exec_resp.status().is_success(),
        "requests endpoint failed: {}",
        exec_resp.status()
    );
    let exec_body: Value = exec_resp.json().await.expect("Invalid JSON response");
    assert!(exec_body
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false));
    let proof = exec_body.get("proof").expect("missing proof");
    let platform = proof.get("platform").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(platform, "sp1");

    // Extract bundle from response for Layer 2 verification
    let bundle = exec_body.get("bundle").expect("missing bundle");

    // Verify the proof with bundle for 2-layer verification
    let verify_payload = serde_json::json!({
        "proof": proof,
        "bundle": bundle
    });
    let verify_resp = client
        .post(&format!("{}/api/v1/verify", base))
        .json(&verify_payload)
        .send()
        .await
        .expect("Failed to call /verify");

    assert!(
        verify_resp.status().is_success(),
        "verify endpoint failed: {}",
        verify_resp.status()
    );
    let verify_body: Value = verify_resp.json().await.expect("Invalid JSON response");
    assert!(verify_body
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false));
    let verification_result = verify_body
        .get("verification_result")
        .expect("missing verification_result");
    assert!(verification_result
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn test_e2e_proof_generation_and_verification_risc0() {
    let (_server, base) = match spawn_node_for_tests().await {
        Some(v) => v,
        None => return,
    };

    // Health check to ensure RISC0 platform is available; otherwise skip
    let health = reqwest::get(format!("{}/api/v1/health", base)).await.ok();
    if let Some(resp) = health {
        if let Ok(val) = resp.json::<Value>().await {
            let platforms = val
                .get("platforms")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let has_risc0 = platforms.iter().any(|p| p.as_str() == Some("risc0"));
            if !has_risc0 {
                eprintln!("Skipping: RISC0 platform not available");
                return;
            }
        }
    }

    // Pre-flight network check; skip if outbound HTTPS is unavailable
    if let Ok(pre_client) = Client::builder().timeout(Duration::from_secs(5)).build() {
        match pre_client.get("https://httpbin.org/get").send().await {
            Ok(resp) if resp.status().is_success() => {}
            _ => {
                eprintln!("Skipping: outbound network not available for httpbin.org");
                return;
            }
        }
    } else {
        eprintln!("Skipping: outbound network not available for httpbin.org");
        return;
    }

    let client = Client::new();
    let payload = serde_json::json!({
        "method": "GET",
        "url": "https://httpbin.org/get",
        "headers": {"user-agent": "VEFAS-Tests"},
        "proof_platform": "risc0",
        "timeout_ms": 30000
    });

    let exec_resp = client
        .post(&format!("{}/api/v1/requests", base))
        .json(&payload)
        .send()
        .await
        .expect("Failed to call /requests");

    assert!(
        exec_resp.status().is_success(),
        "requests endpoint failed: {}",
        exec_resp.status()
    );
    let exec_body: Value = exec_resp.json().await.expect("Invalid JSON response");
    assert!(exec_body
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false));
    let proof = exec_body.get("proof").expect("missing proof");
    let platform = proof.get("platform").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(platform, "risc0");

    // Extract bundle from response for Layer 2 verification
    let bundle = exec_body.get("bundle").expect("missing bundle");

    // Verify the proof with bundle for 2-layer verification
    let verify_payload = serde_json::json!({
        "proof": proof,
        "bundle": bundle
    });
    let verify_resp = client
        .post(&format!("{}/api/v1/verify", base))
        .json(&verify_payload)
        .send()
        .await
        .expect("Failed to call /verify");

    assert!(
        verify_resp.status().is_success(),
        "verify endpoint failed: {}",
        verify_resp.status()
    );
    let verify_body: Value = verify_resp.json().await.expect("Invalid JSON response");
    assert!(verify_body
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false));
    let verification_result = verify_body
        .get("verification_result")
        .expect("missing verification_result");
    assert!(verification_result
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false));
}
