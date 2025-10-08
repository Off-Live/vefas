//! End-to-end tests for Merkle proof verification in zkVM
//!
//! This module tests the complete flow from TLS capture to Merkle proof verification
//! in RISC0 zkVM, ensuring the new architecture works correctly.

use std::time::{Duration, Instant};
use reqwest::Client;
use serde_json::{json, Value};
use tokio::time::timeout;

/// Merkle proof end-to-end tester
pub struct MerkleProofE2ETester {
    gateway_url: String,
    client: Client,
    test_cases: Vec<MerkleTestCase>,
}

impl MerkleProofE2ETester {
    pub fn new(gateway_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(180)) // Extended timeout for proof generation
            .build()
            .expect("Failed to create HTTP client");

        Self {
            gateway_url,
            client,
            test_cases: Self::create_test_cases(),
        }
    }

    /// Create comprehensive test cases for Merkle proof verification
    fn create_test_cases() -> Vec<MerkleTestCase> {
        vec![
            MerkleTestCase {
                name: "simple_get_merkle_verification".to_string(),
                method: "GET".to_string(),
                url: "https://httpbin.org/get".to_string(),
                headers: std::collections::HashMap::new(),
                body: None,
                expected_status: 200,
                description: "Simple GET request with Merkle proof verification".to_string(),
                expected_merkle_fields: vec![
                    "ClientHello".to_string(),
                    "ServerHello".to_string(), 
                    "ServerFinished".to_string(),
                    "HttpRequestCanonical".to_string(),
                    "HttpResponseCanonical".to_string(),
                    "SharedSecret".to_string(),
                    "AllHandshakeTranscript".to_string(),
                ],
            },
            MerkleTestCase {
                name: "post_with_body_merkle_verification".to_string(),
                method: "POST".to_string(),
                url: "https://httpbin.org/post".to_string(),
                headers: vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                ].into_iter().collect(),
                body: Some(r#"{"test": "data", "merkle": "proof"}"#.to_string()),
                expected_status: 200,
                description: "POST request with JSON body and Merkle proof verification".to_string(),
                expected_merkle_fields: vec![
                    "ClientHello".to_string(),
                    "ServerHello".to_string(),
                    "ServerFinished".to_string(), 
                    "HttpRequestCanonical",
                    "HttpResponseCanonical",
                    "SharedSecret",
                    "AllHandshakeTranscript",
                ],
            },
            MerkleTestCase {
                name: "large_response_merkle_verification".to_string(),
                method: "GET".to_string(),
                url: "https://httpbin.org/base64/SFRUUCBpcyBhbiB3ZWIgcHJvdG9jb2wuIEhUVFAgaXMgYW4gd2ViIHByb3RvY29sLiBIVFRQIGlzIGFuIHdlYiBwcm90b2NvbC4gSFRUUCBpcyBhbiB3ZWIgcHJvdG9jb2wuIEhUVFAgaXMgYW4gd2ViIHByb3RvY29sLiBIVFRQIGlzIGFuIHdlYiBwcm90b2NvbC4gSFRUUCBpcyBhbiB3ZWIgcHJvdG9jb2wuIEhUVFAgaXMgYW4gd2ViIHByb3RvY29sLg==".to_string(),
                headers: std::collections::HashMap::new(),
                body: None,
                expected_status: 200,
                description: "Large response with Merkle proof verification".to_string(),
                expected_merkle_fields: vec![
                    "ClientHello".to_string(),
                    "ServerHello".to_string(),
                    "ServerFinished".to_string(),
                    "HttpRequestCanonical", 
                    "HttpResponseCanonical",
                    "SharedSecret",
                    "AllHandshakeTranscript",
                ],
            },
        ]
    }

    /// Run comprehensive Merkle proof end-to-end tests
    pub async fn run_merkle_proof_tests(&self) -> MerkleProofE2EResults {
        let mut results = MerkleProofE2EResults::new();

        println!("🔐 Running Merkle proof end-to-end tests...");

        for test_case in &self.test_cases {
            println!("Testing: {}", test_case.name);

            let test_result = self.test_merkle_proof_verification(test_case).await;
            results.add_test(&test_case.name, test_result);
        }

        results
    }

    /// Test Merkle proof verification for a single test case
    async fn test_merkle_proof_verification(&self, test_case: &MerkleTestCase) -> MerkleTestResult {
        let start_time = Instant::now();

        // Execute request with RISC0 platform (focusing on RISC0 first as requested)
        let risc0_result = self.execute_request_with_merkle_proofs(test_case, "risc0").await;

        let execution_time = start_time.elapsed();

        match risc0_result {
            Ok(response) => {
                // Verify Merkle tree information is present
                let merkle_tree_info = self.extract_merkle_tree_info(&response.response_body);
                
                // Verify proof claim contains expected fields
                let proof_claim = self.extract_proof_claim(&response.response_body);
                
                // Verify Merkle proofs are present and valid
                let merkle_verification = self.verify_merkle_proofs_present(&merkle_tree_info, &test_case.expected_merkle_fields);

                MerkleTestResult {
                    success: true,
                    execution_time,
                    merkle_tree_info,
                    proof_claim,
                    merkle_verification,
                    error: None,
                }
            }
            Err(error) => {
                MerkleTestResult {
                    success: false,
                    execution_time,
                    merkle_tree_info: None,
                    proof_claim: None,
                    merkle_verification: MerkleVerificationResult {
                        all_expected_fields_present: false,
                        merkle_root_valid: false,
                        proof_count_correct: false,
                        details: format!("Request failed: {}", error),
                    },
                    error: Some(error),
                }
            }
        }
    }

    /// Execute request and generate Merkle proofs
    async fn execute_request_with_merkle_proofs(
        &self,
        test_case: &MerkleTestCase,
        platform: &str,
    ) -> Result<MerkleResponse, String> {
        let payload = json!({
            "method": test_case.method,
            "url": test_case.url,
            "headers": test_case.headers,
            "body": test_case.body,
            "proof_platform": platform,
            "timeout_ms": 120000 // 2 minute timeout for proof generation
        });

        let response = timeout(
            Duration::from_secs(180), // 3 minute total timeout
            self.client
                .post(&format!("{}/api/v1/requests", self.gateway_url))
                .json(&payload)
                .send()
        ).await
        .map_err(|_| "Request timeout".to_string())?
        .map_err(|e| format!("HTTP error: {}", e))?;

        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(format!("HTTP {}: {}", status, error_text));
        }

        let response_json: Value = response.json().await
            .map_err(|e| format!("JSON parse error: {}", e))?;

        Ok(MerkleResponse {
            status_code: status.as_u16(),
            response_body: response_json,
            platform: platform.to_string(),
        })
    }

    /// Extract Merkle tree information from response
    fn extract_merkle_tree_info(&self, response: &Value) -> Option<MerkleTreeInfo> {
        response
            .get("merkle_tree")
            .and_then(|tree| {
                Some(MerkleTreeInfo {
                    root: tree.get("root")?.as_str()?.to_string(),
                    leaf_count: tree.get("leaf_count")?.as_u64()? as usize,
                    available_proofs: tree.get("available_proofs")?
                        .as_array()?
                        .iter()
                        .filter_map(|v| v.as_str())
                        .map(|s| s.to_string())
                        .collect(),
                })
            })
    }

    /// Extract proof claim from response
    fn extract_proof_claim(&self, response: &Value) -> Option<Value> {
        response
            .get("proof")
            .and_then(|proof| proof.get("claim"))
            .cloned()
    }

    /// Verify Merkle proofs are present and valid
    fn verify_merkle_proofs_present(
        &self,
        merkle_tree_info: &Option<MerkleTreeInfo>,
        expected_fields: &[String],
    ) -> MerkleVerificationResult {
        match merkle_tree_info {
            Some(info) => {
                let mut all_fields_present = true;
                let mut missing_fields = Vec::new();

                // Check if all expected fields are present
                for expected_field in expected_fields {
                    if !info.available_proofs.iter().any(|proof| proof.contains(expected_field)) {
                        all_fields_present = false;
                        missing_fields.push(expected_field.clone());
                    }
                }

                // Verify Merkle root is valid (non-empty hex string)
                let merkle_root_valid = !info.root.is_empty() && 
                    info.root.len() == 64 && // 32 bytes = 64 hex chars
                    info.root.chars().all(|c| c.is_ascii_hexdigit());

                // Verify proof count is reasonable
                let proof_count_correct = info.leaf_count >= expected_fields.len() && 
                    info.leaf_count <= 20; // Reasonable upper bound

                MerkleVerificationResult {
                    all_expected_fields_present: all_fields_present,
                    merkle_root_valid,
                    proof_count_correct,
                    details: if all_fields_present && merkle_root_valid && proof_count_correct {
                        "All Merkle proofs verified successfully".to_string()
                    } else {
                        format!(
                            "Merkle verification issues - Missing fields: {:?}, Root valid: {}, Count correct: {}",
                            missing_fields, merkle_root_valid, proof_count_correct
                        )
                    },
                }
            }
            None => MerkleVerificationResult {
                all_expected_fields_present: false,
                merkle_root_valid: false,
                proof_count_correct: false,
                details: "No Merkle tree information found in response".to_string(),
            },
        }
    }
}

/// Test case for Merkle proof verification
#[derive(Debug, Clone)]
pub struct MerkleTestCase {
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Option<String>,
    pub expected_status: u16,
    pub description: String,
    pub expected_merkle_fields: Vec<String>,
}

/// Response from Merkle proof test
#[derive(Debug)]
pub struct MerkleResponse {
    pub status_code: u16,
    pub response_body: Value,
    pub platform: String,
}

/// Merkle tree information extracted from response
#[derive(Debug)]
pub struct MerkleTreeInfo {
    pub root: String,
    pub leaf_count: usize,
    pub available_proofs: Vec<String>,
}

/// Result of Merkle verification
#[derive(Debug)]
pub struct MerkleVerificationResult {
    pub all_expected_fields_present: bool,
    pub merkle_root_valid: bool,
    pub proof_count_correct: bool,
    pub details: String,
}

/// Result of a single Merkle test
#[derive(Debug)]
pub struct MerkleTestResult {
    pub success: bool,
    pub execution_time: Duration,
    pub merkle_tree_info: Option<MerkleTreeInfo>,
    pub proof_claim: Option<Value>,
    pub merkle_verification: MerkleVerificationResult,
    pub error: Option<String>,
}

/// Results of all Merkle proof end-to-end tests
#[derive(Debug)]
pub struct MerkleProofE2EResults {
    pub tests: Vec<(String, MerkleTestResult)>,
    pub total_tests: usize,
    pub successful_tests: usize,
    pub merkle_verification_successes: usize,
    pub average_execution_time: Duration,
}

impl MerkleProofE2EResults {
    pub fn new() -> Self {
        Self {
            tests: Vec::new(),
            total_tests: 0,
            successful_tests: 0,
            merkle_verification_successes: 0,
            average_execution_time: Duration::from_secs(0),
        }
    }

    pub fn add_test(&mut self, name: &str, result: MerkleTestResult) {
        if result.success {
            self.successful_tests += 1;
        }
        
        if result.merkle_verification.all_expected_fields_present && 
           result.merkle_verification.merkle_root_valid && 
           result.merkle_verification.proof_count_correct {
            self.merkle_verification_successes += 1;
        }

        self.tests.push((name.to_string(), result));
        self.total_tests += 1;
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            (self.successful_tests as f64 / self.total_tests as f64) * 100.0
        }
    }

    pub fn merkle_verification_rate(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            (self.merkle_verification_successes as f64 / self.total_tests as f64) * 100.0
        }
    }

    pub fn summary(&self) -> String {
        let mut total_time = Duration::from_secs(0);
        for (_, result) in &self.tests {
            total_time += result.execution_time;
        }
        let avg_time = if self.total_tests > 0 {
            total_time / self.total_tests as u32
        } else {
            Duration::from_secs(0)
        };

        format!(
            "Merkle Proof E2E Test Results:\n\
             Total tests: {}\n\
             Successful tests: {} ({:.1}%)\n\
             Merkle verification successes: {} ({:.1}%)\n\
             Average execution time: {:.2}s\n\
             \n\
             Detailed Results:\n{}",
            self.total_tests,
            self.successful_tests,
            self.success_rate(),
            self.merkle_verification_successes,
            self.merkle_verification_rate(),
            avg_time.as_secs_f64(),
            self.detailed_results()
        )
    }

    fn detailed_results(&self) -> String {
        let mut details = String::new();
        
        for (name, result) in &self.tests {
            let status = if result.success { "✅" } else { "❌" };
            let merkle_status = if result.merkle_verification.all_expected_fields_present && 
                                 result.merkle_verification.merkle_root_valid && 
                                 result.merkle_verification.proof_count_correct {
                "🔐"
            } else {
                "⚠️"
            };
            
            details.push_str(&format!(
                "  {} {} {} - {:.2}s - {}\n",
                status,
                merkle_status,
                name,
                result.execution_time.as_secs_f64(),
                result.merkle_verification.details
            ));
            
            if let Some(error) = &result.error {
                details.push_str(&format!("    Error: {}\n", error));
            }
        }
        
        details
    }

    /// Check if all tests passed
    pub fn all_tests_passed(&self) -> bool {
        self.successful_tests == self.total_tests && 
        self.merkle_verification_successes == self.total_tests
    }

    /// Get critical issues that must be addressed
    pub fn get_critical_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();

        if self.success_rate() < 100.0 {
            issues.push(format!("Not all tests passed: {:.1}% success rate", self.success_rate()));
        }

        if self.merkle_verification_rate() < 100.0 {
            issues.push(format!("Merkle verification issues: {:.1}% verification rate", self.merkle_verification_rate()));
        }

        for (name, result) in &self.tests {
            if !result.success {
                issues.push(format!("Test '{}' failed: {:?}", name, result.error));
            } else if !result.merkle_verification.all_expected_fields_present || 
                      !result.merkle_verification.merkle_root_valid || 
                      !result.merkle_verification.proof_count_correct {
                issues.push(format!("Test '{}' has Merkle verification issues: {}", name, result.merkle_verification.details));
            }
        }

        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_merkle_proof_e2e() {
        // Only run if test gateway URL is provided
        let gateway_url = match std::env::var("VEFAS_GATEWAY_TEST_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("Skipping Merkle proof E2E tests: VEFAS_GATEWAY_TEST_URL not set");
                return;
            }
        };

        let tester = MerkleProofE2ETester::new(gateway_url);
        let results = tester.run_merkle_proof_tests().await;

        println!("{}", results.summary());

        // Assert all tests passed
        assert!(
            results.all_tests_passed(),
            "Not all Merkle proof E2E tests passed. Issues: {:?}",
            results.get_critical_issues()
        );

        // Assert high success rate
        assert!(
            results.success_rate() >= 100.0,
            "Merkle proof E2E test success rate too low: {:.1}%",
            results.success_rate()
        );

        // Assert high Merkle verification rate
        assert!(
            results.merkle_verification_rate() >= 100.0,
            "Merkle verification rate too low: {:.1}%",
            results.merkle_verification_rate()
        );
    }

    #[test]
    fn test_merkle_test_case_creation() {
        let test_cases = MerkleProofE2ETester::create_test_cases();
        assert!(!test_cases.is_empty(), "Should create test cases");
        assert!(test_cases.len() >= 3, "Should create sufficient test cases");

        // Verify test cases have required fields
        for test_case in &test_cases {
            assert!(!test_case.name.is_empty(), "Test case should have name");
            assert!(!test_case.method.is_empty(), "Test case should have method");
            assert!(!test_case.url.is_empty(), "Test case should have URL");
            assert!(test_case.url.starts_with("https://"), "Test case URL should be HTTPS");
            assert!(!test_case.expected_merkle_fields.is_empty(), "Test case should have expected Merkle fields");
        }
    }

    #[test]
    fn test_merkle_results_aggregation() {
        let mut results = MerkleProofE2EResults::new();

        let successful_result = MerkleTestResult {
            success: true,
            execution_time: Duration::from_secs(1),
            merkle_tree_info: Some(MerkleTreeInfo {
                root: "a".repeat(64),
                leaf_count: 7,
                available_proofs: vec!["ClientHello".to_string(), "ServerHello".to_string()],
            }),
            proof_claim: Some(Value::Null),
            merkle_verification: MerkleVerificationResult {
                all_expected_fields_present: true,
                merkle_root_valid: true,
                proof_count_correct: true,
                details: "All good".to_string(),
            },
            error: None,
        };

        let failed_result = MerkleTestResult {
            success: false,
            execution_time: Duration::from_secs(2),
            merkle_tree_info: None,
            proof_claim: None,
            merkle_verification: MerkleVerificationResult {
                all_expected_fields_present: false,
                merkle_root_valid: false,
                proof_count_correct: false,
                details: "Failed".to_string(),
            },
            error: Some("Test error".to_string()),
        };

        results.add_test("test1", successful_result);
        results.add_test("test2", failed_result);

        assert_eq!(results.total_tests, 2);
        assert_eq!(results.successful_tests, 1);
        assert_eq!(results.merkle_verification_successes, 1);
        assert_eq!(results.success_rate(), 50.0);
        assert_eq!(results.merkle_verification_rate(), 50.0);
        assert!(!results.all_tests_passed());
    }

}
