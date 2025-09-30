//! Cross-platform consistency tests for VEFAS
//!
//! This module ensures that SP1 and RISC0 implementations produce
//! identical results for the same inputs, validating cross-platform
//! consistency and correctness.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use reqwest::Client;
use serde_json::{json, Value};
use tokio::time::timeout;

/// Cross-platform consistency tester
pub struct CrossPlatformTester {
    gateway_url: String,
    client: Client,
    test_vectors: Vec<TestVector>,
}

impl CrossPlatformTester {
    pub fn new(gateway_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(120)) // Extended timeout for proof generation
            .build()
            .expect("Failed to create HTTP client");

        Self {
            gateway_url,
            client,
            test_vectors: Self::create_test_vectors(),
        }
    }

    /// Create comprehensive test vectors for cross-platform validation
    fn create_test_vectors() -> Vec<TestVector> {
        vec![
            TestVector {
                name: "simple_get_request".to_string(),
                method: "GET".to_string(),
                url: "https://httpbin.org/get".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                description: "Simple GET request with no headers or body".to_string(),
            },
            TestVector {
                name: "get_with_headers".to_string(),
                method: "GET".to_string(),
                url: "https://httpbin.org/headers".to_string(),
                headers: vec![
                    ("User-Agent".to_string(), "VEFAS/1.0".to_string()),
                    ("Accept".to_string(), "application/json".to_string()),
                    ("X-Custom-Header".to_string(), "test-value".to_string()),
                ].into_iter().collect(),
                body: None,
                expected_status: 200,
                description: "GET request with custom headers".to_string(),
            },
            TestVector {
                name: "post_with_json_body".to_string(),
                method: "POST".to_string(),
                url: "https://httpbin.org/post".to_string(),
                headers: vec![
                    ("Content-Type".to_string(), "application/json".to_string()),
                ].into_iter().collect(),
                body: Some(r#"{"key": "value", "number": 42, "nested": {"inner": "data"}}"#.to_string()),
                expected_status: 200,
                description: "POST request with JSON body".to_string(),
            },
            TestVector {
                name: "post_with_form_data".to_string(),
                method: "POST".to_string(),
                url: "https://httpbin.org/post".to_string(),
                headers: vec![
                    ("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()),
                ].into_iter().collect(),
                body: Some("field1=value1&field2=value2&field3=special%20chars".to_string()),
                expected_status: 200,
                description: "POST request with form data".to_string(),
            },
            TestVector {
                name: "put_request".to_string(),
                method: "PUT".to_string(),
                url: "https://httpbin.org/put".to_string(),
                headers: vec![
                    ("Content-Type".to_string(), "text/plain".to_string()),
                ].into_iter().collect(),
                body: Some("This is plain text data for PUT request".to_string()),
                expected_status: 200,
                description: "PUT request with plain text body".to_string(),
            },
            TestVector {
                name: "delete_request".to_string(),
                method: "DELETE".to_string(),
                url: "https://httpbin.org/delete".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                description: "DELETE request".to_string(),
            },
            TestVector {
                name: "request_with_query_params".to_string(),
                method: "GET".to_string(),
                url: "https://httpbin.org/get?param1=value1&param2=value2&param3=special%20chars".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                description: "GET request with query parameters".to_string(),
            },
            TestVector {
                name: "large_response_body".to_string(),
                method: "GET".to_string(),
                url: "https://httpbin.org/base64/SFRUUCBpcyBhbiB3ZWIgcHJvdG9jb2wuIEhUVFAgaXMgYW4gd2ViIHByb3RvY29sLiBIVFRQIGlzIGFuIHdlYiBwcm90b2NvbC4gSFRUUCBpcyBhbiB3ZWIgcHJvdG9jb2wuIEhUVFAgaXMgYW4gd2ViIHByb3RvY29sLiBIVFRQIGlzIGFuIHdlYiBwcm90b2NvbC4gSFRUUCBpcyBhbiB3ZWIgcHJvdG9jb2wuIEhUVFAgaXMgYW4gd2ViIHByb3RvY29sLg==".to_string(),
                headers: HashMap::new(),
                body: None,
                expected_status: 200,
                description: "Request returning larger response body".to_string(),
            },
        ]
    }

    /// Run cross-platform consistency tests
    pub async fn run_consistency_tests(&self) -> CrossPlatformResults {
        let mut results = CrossPlatformResults::new();

        println!("🔄 Running cross-platform consistency tests...");

        for test_vector in &self.test_vectors {
            println!("Testing: {}", test_vector.name);

            let consistency_result = self.test_platform_consistency(test_vector).await;
            results.add_test(&test_vector.name, consistency_result);
        }

        results
    }

    /// Test consistency between SP1 and RISC0 platforms for a single test vector
    async fn test_platform_consistency(&self, test_vector: &TestVector) -> ConsistencyTestResult {
        // Execute the same request on both platforms
        let sp1_result = self.execute_request_on_platform(test_vector, "sp1").await;
        let risc0_result = self.execute_request_on_platform(test_vector, "risc0").await;

        match (sp1_result, risc0_result) {
            (Ok(sp1_response), Ok(risc0_response)) => {
                self.compare_platform_responses(sp1_response, risc0_response)
            }
            (Err(sp1_error), Ok(_)) => ConsistencyTestResult {
                consistent: false,
                sp1_success: false,
                risc0_success: true,
                details: format!("SP1 failed: {}", sp1_error),
                performance_comparison: None,
            },
            (Ok(_), Err(risc0_error)) => ConsistencyTestResult {
                consistent: false,
                sp1_success: true,
                risc0_success: false,
                details: format!("RISC0 failed: {}", risc0_error),
                performance_comparison: None,
            },
            (Err(sp1_error), Err(risc0_error)) => ConsistencyTestResult {
                consistent: true, // Both failed consistently
                sp1_success: false,
                risc0_success: false,
                details: format!("Both platforms failed - SP1: {}, RISC0: {}", sp1_error, risc0_error),
                performance_comparison: None,
            },
        }
    }

    /// Execute a request on a specific platform
    async fn execute_request_on_platform(
        &self,
        test_vector: &TestVector,
        platform: &str,
    ) -> Result<PlatformResponse, String> {
        let payload = json!({
            "method": test_vector.method,
            "url": test_vector.url,
            "headers": test_vector.headers,
            "body": test_vector.body,
            "proof_platform": platform,
            "timeout_ms": 60000 // 60 second timeout for proof generation
        });

        let start_time = Instant::now();

        let response = timeout(
            Duration::from_secs(120), // 2 minute total timeout
            self.client
                .post(&format!("{}/api/v1/requests", self.gateway_url))
                .json(&payload)
                .send()
        ).await
        .map_err(|_| "Request timeout".to_string())?
        .map_err(|e| format!("HTTP error: {}", e))?;

        let execution_time = start_time.elapsed();
        let status = response.status();

        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(format!("HTTP {}: {}", status, error_text));
        }

        let response_json: Value = response.json().await
            .map_err(|e| format!("JSON parse error: {}", e))?;

        Ok(PlatformResponse {
            status_code: status.as_u16(),
            response_body: response_json,
            execution_time,
            platform: platform.to_string(),
        })
    }

    /// Compare responses from both platforms for consistency
    fn compare_platform_responses(
        &self,
        sp1_response: PlatformResponse,
        risc0_response: PlatformResponse,
    ) -> ConsistencyTestResult {
        let mut inconsistencies = Vec::new();
        let mut consistent = true;

        // Check if both requests succeeded
        let both_succeeded = sp1_response.status_code == 200 && risc0_response.status_code == 200;

        if !both_succeeded {
            inconsistencies.push(format!(
                "Status codes differ - SP1: {}, RISC0: {}",
                sp1_response.status_code, risc0_response.status_code
            ));
            consistent = false;
        }

        if both_succeeded {
            // Extract and compare proof claims
            let sp1_claim = self.extract_proof_claim(&sp1_response.response_body);
            let risc0_claim = self.extract_proof_claim(&risc0_response.response_body);

            match (sp1_claim, risc0_claim) {
                (Some(sp1_claim), Some(risc0_claim)) => {
                    // Compare critical claim fields
                    if sp1_claim.get("domain") != risc0_claim.get("domain") {
                        inconsistencies.push("Domain claims differ".to_string());
                        consistent = false;
                    }

                    if sp1_claim.get("method") != risc0_claim.get("method") {
                        inconsistencies.push("Method claims differ".to_string());
                        consistent = false;
                    }

                    if sp1_claim.get("path") != risc0_claim.get("path") {
                        inconsistencies.push("Path claims differ".to_string());
                        consistent = false;
                    }

                    if sp1_claim.get("status_code") != risc0_claim.get("status_code") {
                        inconsistencies.push("Status code claims differ".to_string());
                        consistent = false;
                    }

                    // Note: Request and response hashes may differ due to timestamp differences
                    // TLS handshake randomness, etc. This is expected and not an inconsistency.
                }
                (None, Some(_)) => {
                    inconsistencies.push("SP1 missing proof claim".to_string());
                    consistent = false;
                }
                (Some(_), None) => {
                    inconsistencies.push("RISC0 missing proof claim".to_string());
                    consistent = false;
                }
                (None, None) => {
                    inconsistencies.push("Both platforms missing proof claims".to_string());
                    consistent = false;
                }
            }
        }

        let performance_comparison = Some(PerformanceComparison {
            sp1_execution_time: sp1_response.execution_time,
            risc0_execution_time: risc0_response.execution_time,
            sp1_faster: sp1_response.execution_time < risc0_response.execution_time,
            time_difference: if sp1_response.execution_time > risc0_response.execution_time {
                sp1_response.execution_time - risc0_response.execution_time
            } else {
                risc0_response.execution_time - sp1_response.execution_time
            },
        });

        ConsistencyTestResult {
            consistent,
            sp1_success: sp1_response.status_code == 200,
            risc0_success: risc0_response.status_code == 200,
            details: if inconsistencies.is_empty() {
                "Platforms produce consistent results".to_string()
            } else {
                format!("Inconsistencies: {}", inconsistencies.join(", "))
            },
            performance_comparison,
        }
    }

    /// Extract proof claim from response
    fn extract_proof_claim(&self, response: &Value) -> Option<&Value> {
        response
            .get("proof")
            .and_then(|proof| proof.get("claim"))
    }
}

/// Test vector for cross-platform testing
#[derive(Debug, Clone)]
pub struct TestVector {
    pub name: String,
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub expected_status: u16,
    pub description: String,
}

/// Response from a single platform
#[derive(Debug)]
pub struct PlatformResponse {
    pub status_code: u16,
    pub response_body: Value,
    pub execution_time: Duration,
    pub platform: String,
}

/// Result of consistency test between platforms
#[derive(Debug)]
pub struct ConsistencyTestResult {
    pub consistent: bool,
    pub sp1_success: bool,
    pub risc0_success: bool,
    pub details: String,
    pub performance_comparison: Option<PerformanceComparison>,
}

/// Performance comparison between platforms
#[derive(Debug)]
pub struct PerformanceComparison {
    pub sp1_execution_time: Duration,
    pub risc0_execution_time: Duration,
    pub sp1_faster: bool,
    pub time_difference: Duration,
}

/// Results of all cross-platform consistency tests
#[derive(Debug)]
pub struct CrossPlatformResults {
    pub tests: Vec<(String, ConsistencyTestResult)>,
    pub total_tests: usize,
    pub consistent_tests: usize,
    pub sp1_successes: usize,
    pub risc0_successes: usize,
}

impl CrossPlatformResults {
    pub fn new() -> Self {
        Self {
            tests: Vec::new(),
            total_tests: 0,
            consistent_tests: 0,
            sp1_successes: 0,
            risc0_successes: 0,
        }
    }

    pub fn add_test(&mut self, name: &str, result: ConsistencyTestResult) {
        if result.consistent {
            self.consistent_tests += 1;
        }
        if result.sp1_success {
            self.sp1_successes += 1;
        }
        if result.risc0_success {
            self.risc0_successes += 1;
        }

        self.tests.push((name.to_string(), result));
        self.total_tests += 1;
    }

    pub fn consistency_rate(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            (self.consistent_tests as f64 / self.total_tests as f64) * 100.0
        }
    }

    pub fn sp1_success_rate(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            (self.sp1_successes as f64 / self.total_tests as f64) * 100.0
        }
    }

    pub fn risc0_success_rate(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            (self.risc0_successes as f64 / self.total_tests as f64) * 100.0
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "Cross-Platform Consistency Results:\n\
             Total tests: {}\n\
             Consistent results: {} ({:.1}%)\n\
             SP1 success rate: {:.1}%\n\
             RISC0 success rate: {:.1}%\n\
             \n\
             Performance Summary:\n{}",
            self.total_tests,
            self.consistent_tests,
            self.consistency_rate(),
            self.sp1_success_rate(),
            self.risc0_success_rate(),
            self.performance_summary()
        )
    }

    fn performance_summary(&self) -> String {
        let mut sp1_wins = 0;
        let mut risc0_wins = 0;
        let mut total_sp1_time = Duration::from_secs(0);
        let mut total_risc0_time = Duration::from_secs(0);
        let mut count = 0;

        for (_, result) in &self.tests {
            if let Some(perf) = &result.performance_comparison {
                if perf.sp1_faster {
                    sp1_wins += 1;
                } else {
                    risc0_wins += 1;
                }
                total_sp1_time += perf.sp1_execution_time;
                total_risc0_time += perf.risc0_execution_time;
                count += 1;
            }
        }

        if count == 0 {
            "No performance data available".to_string()
        } else {
            let avg_sp1_time = total_sp1_time / count as u32;
            let avg_risc0_time = total_risc0_time / count as u32;

            format!(
                "SP1 faster: {} times, RISC0 faster: {} times\n\
                 Average SP1 time: {:.2}s\n\
                 Average RISC0 time: {:.2}s",
                sp1_wins,
                risc0_wins,
                avg_sp1_time.as_secs_f64(),
                avg_risc0_time.as_secs_f64()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cross_platform_consistency() {
        // Only run if test gateway URL is provided
        let gateway_url = match std::env::var("VEFAS_GATEWAY_TEST_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("Skipping cross-platform tests: VEFAS_GATEWAY_TEST_URL not set");
                return;
            }
        };

        let tester = CrossPlatformTester::new(gateway_url);
        let results = tester.run_consistency_tests().await;

        println!("{}", results.summary());

        // Assert high consistency rate
        assert!(
            results.consistency_rate() >= 95.0,
            "Cross-platform consistency rate too low: {:.1}%",
            results.consistency_rate()
        );

        // Assert both platforms have reasonable success rates
        assert!(
            results.sp1_success_rate() >= 80.0,
            "SP1 success rate too low: {:.1}%",
            results.sp1_success_rate()
        );

        assert!(
            results.risc0_success_rate() >= 80.0,
            "RISC0 success rate too low: {:.1}%",
            results.risc0_success_rate()
        );
    }

    #[test]
    fn test_test_vector_creation() {
        let vectors = CrossPlatformTester::create_test_vectors();
        assert!(!vectors.is_empty(), "Should create test vectors");
        assert!(vectors.len() >= 5, "Should create sufficient test vectors");

        // Verify test vectors have required fields
        for vector in &vectors {
            assert!(!vector.name.is_empty(), "Test vector should have name");
            assert!(!vector.method.is_empty(), "Test vector should have method");
            assert!(!vector.url.is_empty(), "Test vector should have URL");
            assert!(vector.url.starts_with("https://"), "Test vector URL should be HTTPS");
        }
    }

    #[test]
    fn test_cross_platform_results_aggregation() {
        let mut results = CrossPlatformResults::new();

        let consistent_result = ConsistencyTestResult {
            consistent: true,
            sp1_success: true,
            risc0_success: true,
            details: "Test passed".to_string(),
            performance_comparison: None,
        };

        let inconsistent_result = ConsistencyTestResult {
            consistent: false,
            sp1_success: true,
            risc0_success: false,
            details: "RISC0 failed".to_string(),
            performance_comparison: None,
        };

        results.add_test("test1", consistent_result);
        results.add_test("test2", inconsistent_result);

        assert_eq!(results.total_tests, 2);
        assert_eq!(results.consistent_tests, 1);
        assert_eq!(results.sp1_successes, 2);
        assert_eq!(results.risc0_successes, 1);
        assert_eq!(results.consistency_rate(), 50.0);
        assert_eq!(results.sp1_success_rate(), 100.0);
        assert_eq!(results.risc0_success_rate(), 50.0);
    }
}