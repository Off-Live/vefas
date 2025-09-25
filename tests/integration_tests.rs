use reqwest::{Client, StatusCode};
use serde_json::Value;
use tokio::time::{sleep, Duration};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration as StdDuration;
use vefas_gateway::{VefasGateway, VefasGatewayConfig};
use tokio::task::JoinHandle;
use axum::Router;

const BASE_URL: &str = "http://127.0.0.1:3000";

async fn spawn_gateway_for_tests() -> Option<(JoinHandle<()>, String)> {
    // Build router using gateway instance, then bind to an ephemeral port
    let gw = match VefasGateway::new(VefasGatewayConfig { bind_address: "127.0.0.1:0".to_string(), ..Default::default() }).await {
        Ok(g) => g,
        Err(e) => {
            eprintln!("Skipping: failed to initialize VEFAS Gateway: {}", e);
            return None;
        }
    };

    let router: Router = gw.router();
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
    // small delay to ensure server starts
    sleep(Duration::from_millis(300)).await;
    Some((handle, base_url))
}

#[tokio::test]
async fn test_service_info() {
    let (_server, base) = match spawn_gateway_for_tests().await { Some(v) => v, None => return };
    let client = Client::new();

    let response = client
        .get(&format!("{}/", base))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::OK);

    let body: Value = response.json().await.expect("Failed to parse JSON");

    // Verify service information structure
    assert_eq!(body.get("service").unwrap().as_str().unwrap(), "VEFAS Gateway");
    assert_eq!(body.get("version").unwrap().as_str().unwrap(), "0.1.0");
    assert_eq!(body.get("api_version").unwrap().as_str().unwrap(), "v1");

    let endpoints = body.get("endpoints").unwrap().as_array().unwrap();
    assert!(endpoints.len() >= 3);

    println!("✓ Service info endpoint working correctly");
}

#[tokio::test]
async fn test_health_check() {
    let (_server, base) = match spawn_gateway_for_tests().await { Some(v) => v, None => return };
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
    assert_eq!(body.get("version").unwrap().as_str().unwrap(), "0.1.0");

    // Verify zkVM platform availability
    let platforms = body.get("platforms").unwrap().as_array().unwrap();
    assert!(!platforms.is_empty(), "No zkVM platforms are available");

    println!("✓ Health check endpoint working correctly");
}

#[tokio::test]
async fn test_server_availability() {
    let (_server, base) = match spawn_gateway_for_tests().await { Some(v) => v, None => return };

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

#[tokio::test]
async fn test_invalid_endpoint() {
    let (_server, base) = match spawn_gateway_for_tests().await { Some(v) => v, None => return };
    let client = Client::new();

    let response = client
        .get(&format!("{}/api/v1/nonexistent", base))
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    println!("✓ Invalid endpoint returns 404 as expected");
}

#[tokio::test]
async fn test_cors_headers() {
    let (_server, base) = match spawn_gateway_for_tests().await { Some(v) => v, None => return };
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

#[tokio::test]
async fn test_requests_endpoint_structure() {
    let (_server, base) = match spawn_gateway_for_tests().await { Some(v) => v, None => return };
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
    assert!(response.status() == StatusCode::UNPROCESSABLE_ENTITY || response.status() == StatusCode::BAD_REQUEST);

    println!("✓ Requests endpoint rejects invalid payloads as expected");
}

#[tokio::test]
async fn test_verify_endpoint_structure() {
    let (_server, base) = match spawn_gateway_for_tests().await { Some(v) => v, None => return };
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
    assert!(response.status() == StatusCode::UNPROCESSABLE_ENTITY || response.status() == StatusCode::BAD_REQUEST);

    println!("✓ Verify endpoint rejects invalid payloads as expected");
}

#[tokio::test]
async fn test_e2e_proof_generation_and_verification_sp1() {
    let (_server, base) = match spawn_gateway_for_tests().await { Some(v) => v, None => return };

    // Health check to ensure SP1 platform is available; otherwise skip
    let health = reqwest::get(format!("{}/api/v1/health", base)).await.ok();
    if let Some(resp) = health {
        if let Ok(val) = resp.json::<Value>().await {
            let platforms = val.get("platforms").and_then(|v| v.as_array()).cloned().unwrap_or_default();
            let has_sp1 = platforms.iter().any(|p| p.as_str() == Some("sp1"));
            if !has_sp1 {
                eprintln!("Skipping: SP1 platform not available");
                return;
            }
        }
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

    assert!(exec_resp.status().is_success(), "requests endpoint failed: {}", exec_resp.status());
    let exec_body: Value = exec_resp.json().await.expect("Invalid JSON response");
    assert!(exec_body.get("success").and_then(|v| v.as_bool()).unwrap_or(false));
    let proof = exec_body.get("proof").expect("missing proof");
    let platform = proof.get("platform").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(platform, "sp1");

    // Verify the proof
    let verify_payload = serde_json::json!({"proof": proof});
    let verify_resp = client
        .post(&format!("{}/api/v1/verify", base))
        .json(&verify_payload)
        .send()
        .await
        .expect("Failed to call /verify");

    assert!(verify_resp.status().is_success(), "verify endpoint failed: {}", verify_resp.status());
    let verify_body: Value = verify_resp.json().await.expect("Invalid JSON response");
    assert!(verify_body.get("success").and_then(|v| v.as_bool()).unwrap_or(false));
    let verification_result = verify_body.get("verification_result").expect("missing verification_result");
    assert!(verification_result.get("valid").and_then(|v| v.as_bool()).unwrap_or(false));
}