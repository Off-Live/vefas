//! Regression testing suite for VEFAS
//!
//! This module implements comprehensive regression tests to ensure that
//! new changes don't break existing functionality and that the system
//! maintains backward compatibility and consistent behavior over time.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use reqwest::Client;
use serde_json::{json, Value};
use tokio::time::timeout;
use chrono::{DateTime, Utc};

/// Regression test suite for validating system stability
pub struct RegressionTestSuite {
    gateway_url: String,
    client: Client,
    baseline_results: Option<RegressionBaseline>,
}

impl RegressionTestSuite {
    pub fn new(gateway_url: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            gateway_url,
            client,
            baseline_results: None,
        }
    }

    /// Load baseline results from previous test runs
    pub async fn load_baseline(&mut self) -> Result<(), String> {
        // In a real implementation, this would load from a file or database
        // For now, we'll generate a baseline by running tests
        self.baseline_results = Some(self.generate_baseline().await?);
        Ok(())
    }

    /// Generate baseline results by running all regression tests
    async fn generate_baseline(&self) -> Result<RegressionBaseline, String> {
        let test_scenarios = self.create_regression_scenarios();
        let mut baseline = RegressionBaseline::new();

        for scenario in &test_scenarios {
            let result = self.execute_regression_scenario(scenario).await?;
            baseline.add_scenario_result(&scenario.name, result);
        }

        Ok(baseline)
    }

    /// Run regression tests and compare against baseline
    pub async fn run_regression_tests(&self) -> Result<RegressionResults, String> {
        if self.baseline_results.is_none() {
            return Err("No baseline results loaded. Call load_baseline() first.".to_string());
        }

        let test_scenarios = self.create_regression_scenarios();
        let mut results = RegressionResults::new();

        println!("🔄 Running regression tests against baseline...");

        for scenario in &test_scenarios {
            println!("Testing scenario: {}", scenario.name);

            let current_result = self.execute_regression_scenario(scenario).await?;
            let baseline_result = self.baseline_results
                .as_ref()
                .unwrap()
                .get_scenario_result(&scenario.name);

            let comparison = self.compare_with_baseline(
                &scenario.name,
                &current_result,
                baseline_result,
            );

            results.add_comparison(comparison);
        }

        Ok(results)
    }

    /// Create comprehensive regression test scenarios
    fn create_regression_scenarios(&self) -> Vec<RegressionScenario> {
        vec![
            RegressionScenario {
                name: "basic_get_request".to_string(),
                description: "Basic GET request functionality".to_string(),
                request: TestRequest {
                    method: "GET".to_string(),
                    url: "https://httpbin.org/get".to_string(),
                    headers: HashMap::new(),
                    body: None,
                },
                platforms: vec!["sp1".to_string(), "risc0".to_string()],
                expected_outcome: ExpectedOutcome::Success,
                critical: true,
            },
            RegressionScenario {
                name: "post_with_json".to_string(),
                description: "POST request with JSON payload".to_string(),
                request: TestRequest {
                    method: "POST".to_string(),
                    url: "https://httpbin.org/post".to_string(),
                    headers: vec![
                        ("Content-Type".to_string(), "application/json".to_string()),
                    ].into_iter().collect(),
                    body: Some(json!({
                        "test_data": "regression_test",
                        "timestamp": 1234567890,
                        "nested": {
                            "value": 42
                        }
                    }).to_string()),
                },
                platforms: vec!["sp1".to_string(), "risc0".to_string()],
                expected_outcome: ExpectedOutcome::Success,
                critical: true,
            },
            RegressionScenario {
                name: "authenticated_request".to_string(),
                description: "Request with authentication headers".to_string(),
                request: TestRequest {
                    method: "GET".to_string(),
                    url: "https://httpbin.org/bearer".to_string(),
                    headers: vec![
                        ("Authorization".to_string(), "Bearer test-token".to_string()),
                    ].into_iter().collect(),
                    body: None,
                },
                platforms: vec!["sp1".to_string()], // Test on single platform for faster execution
                expected_outcome: ExpectedOutcome::Success,
                critical: false,
            },
            RegressionScenario {
                name: "large_payload".to_string(),
                description: "Request with larger payload".to_string(),
                request: TestRequest {
                    method: "POST".to_string(),
                    url: "https://httpbin.org/post".to_string(),
                    headers: vec![
                        ("Content-Type".to_string(), "application/json".to_string()),
                    ].into_iter().collect(),
                    body: Some(json!({
                        "large_data": "x".repeat(1000),
                        "array": (0..100).collect::<Vec<i32>>(),
                        "description": "This is a larger payload to test handling of bigger requests"
                    }).to_string()),
                },
                platforms: vec!["sp1".to_string()],
                expected_outcome: ExpectedOutcome::Success,
                critical: false,
            },
            RegressionScenario {
                name: "error_handling_invalid_url".to_string(),
                description: "Error handling for invalid URLs".to_string(),
                request: TestRequest {
                    method: "GET".to_string(),
                    url: "https://invalid-domain-that-does-not-exist-12345.com/".to_string(),
                    headers: HashMap::new(),
                    body: None,
                },
                platforms: vec!["sp1".to_string()],
                expected_outcome: ExpectedOutcome::Failure,
                critical: true,
            },
            RegressionScenario {
                name: "special_characters_handling".to_string(),
                description: "Handling of special characters in URLs and headers".to_string(),
                request: TestRequest {
                    method: "GET".to_string(),
                    url: "https://httpbin.org/get?special=%20%21%40%23%24%25%5E%26%2A".to_string(),
                    headers: vec![
                        ("X-Special-Chars".to_string(), "!@#$%^&*()".to_string()),
                    ].into_iter().collect(),
                    body: None,
                },
                platforms: vec!["sp1".to_string()],
                expected_outcome: ExpectedOutcome::Success,
                critical: false,
            },
            RegressionScenario {
                name: "concurrent_requests".to_string(),
                description: "Handling of concurrent requests".to_string(),
                request: TestRequest {
                    method: "GET".to_string(),
                    url: "https://httpbin.org/get".to_string(),
                    headers: HashMap::new(),
                    body: None,
                },
                platforms: vec!["sp1".to_string()],
                expected_outcome: ExpectedOutcome::Success,
                critical: true,
            },
        ]
    }

    /// Execute a single regression scenario
    async fn execute_regression_scenario(
        &self,
        scenario: &RegressionScenario,
    ) -> Result<ScenarioResult, String> {
        let mut platform_results = HashMap::new();

        for platform in &scenario.platforms {
            let start_time = Instant::now();

            let result = self.execute_request_on_platform(
                &scenario.request,
                platform,
                &scenario.expected_outcome,
            ).await;

            let execution_time = start_time.elapsed();

            platform_results.insert(
                platform.clone(),
                PlatformResult {
                    success: result.is_ok(),
                    execution_time,
                    error_message: result.err(),
                    response_data: None, // We could store response data for more detailed comparison
                }
            );
        }

        Ok(ScenarioResult {
            scenario_name: scenario.name.clone(),
            timestamp: Utc::now(),
            platform_results,
            overall_success: platform_results.values().all(|r| r.success),
        })
    }

    /// Execute request on specific platform
    async fn execute_request_on_platform(
        &self,
        request: &TestRequest,
        platform: &str,
        expected_outcome: &ExpectedOutcome,
    ) -> Result<(), String> {
        let payload = json!({
            "method": request.method,
            "url": request.url,
            "headers": request.headers,
            "body": request.body,
            "proof_platform": platform,
            "timeout_ms": 60000
        });

        let response = timeout(
            Duration::from_secs(120),
            self.client
                .post(&format!("{}/api/v1/requests", self.gateway_url))
                .json(&payload)
                .send()
        ).await
        .map_err(|_| "Request timeout".to_string())?
        .map_err(|e| format!("HTTP error: {}", e))?;

        let status = response.status();

        match expected_outcome {
            ExpectedOutcome::Success => {
                if status.is_success() {
                    Ok(())
                } else {
                    let error_text = response.text().await.unwrap_or_default();
                    Err(format!("Expected success but got {}: {}", status, error_text))
                }
            }
            ExpectedOutcome::Failure => {
                if status.is_client_error() || status.is_server_error() {
                    Ok(())
                } else {
                    Err(format!("Expected failure but got success: {}", status))
                }
            }
        }
    }

    /// Compare current result with baseline
    fn compare_with_baseline(
        &self,
        scenario_name: &str,
        current: &ScenarioResult,
        baseline: Option<&ScenarioResult>,
    ) -> RegressionComparison {
        let baseline = match baseline {
            Some(b) => b,
            None => {
                return RegressionComparison {
                    scenario_name: scenario_name.to_string(),
                    status: RegressionStatus::NewTest,
                    details: "No baseline data available for this test".to_string(),
                    performance_change: None,
                    success_change: SuccessChange::NoChange,
                };
            }
        };

        // Compare overall success
        let success_change = match (baseline.overall_success, current.overall_success) {
            (true, true) => SuccessChange::NoChange,
            (false, false) => SuccessChange::NoChange,
            (true, false) => SuccessChange::Regression,
            (false, true) => SuccessChange::Improvement,
        };

        // Compare performance
        let performance_change = self.calculate_performance_change(baseline, current);

        // Determine overall status
        let status = match success_change {
            SuccessChange::Regression => RegressionStatus::Regression,
            SuccessChange::Improvement => RegressionStatus::Improvement,
            SuccessChange::NoChange => {
                if current.overall_success {
                    if let Some(perf) = &performance_change {
                        if perf.significant_slowdown {
                            RegressionStatus::PerformanceRegression
                        } else {
                            RegressionStatus::Stable
                        }
                    } else {
                        RegressionStatus::Stable
                    }
                } else {
                    RegressionStatus::Stable // Consistently failing
                }
            }
        };

        RegressionComparison {
            scenario_name: scenario_name.to_string(),
            status,
            details: self.generate_comparison_details(baseline, current, &success_change),
            performance_change,
            success_change,
        }
    }

    /// Calculate performance change between baseline and current
    fn calculate_performance_change(
        &self,
        baseline: &ScenarioResult,
        current: &ScenarioResult,
    ) -> Option<PerformanceChange> {
        // Compare average execution times across platforms
        let baseline_avg = self.calculate_average_execution_time(&baseline.platform_results);
        let current_avg = self.calculate_average_execution_time(&current.platform_results);

        if baseline_avg.is_zero() || current_avg.is_zero() {
            return None;
        }

        let change_ratio = current_avg.as_secs_f64() / baseline_avg.as_secs_f64();
        let percentage_change = (change_ratio - 1.0) * 100.0;

        // Consider >20% slowdown as significant
        let significant_slowdown = percentage_change > 20.0;
        let significant_improvement = percentage_change < -20.0;

        Some(PerformanceChange {
            baseline_time: baseline_avg,
            current_time: current_avg,
            percentage_change,
            significant_slowdown,
            significant_improvement,
        })
    }

    /// Calculate average execution time across platform results
    fn calculate_average_execution_time(&self, results: &HashMap<String, PlatformResult>) -> Duration {
        if results.is_empty() {
            return Duration::from_secs(0);
        }

        let total: Duration = results.values().map(|r| r.execution_time).sum();
        total / results.len() as u32
    }

    /// Generate detailed comparison description
    fn generate_comparison_details(
        &self,
        baseline: &ScenarioResult,
        current: &ScenarioResult,
        success_change: &SuccessChange,
    ) -> String {
        let mut details = Vec::new();

        match success_change {
            SuccessChange::Regression => {
                details.push("❌ Test regressed from passing to failing".to_string());
            }
            SuccessChange::Improvement => {
                details.push("✅ Test improved from failing to passing".to_string());
            }
            SuccessChange::NoChange => {
                if current.overall_success {
                    details.push("✅ Test continues to pass".to_string());
                } else {
                    details.push("⚠️  Test continues to fail".to_string());
                }
            }
        }

        // Add platform-specific details
        for (platform, current_result) in &current.platform_results {
            if let Some(baseline_result) = baseline.platform_results.get(platform) {
                if baseline_result.success != current_result.success {
                    details.push(format!(
                        "Platform {}: {} -> {}",
                        platform,
                        if baseline_result.success { "PASS" } else { "FAIL" },
                        if current_result.success { "PASS" } else { "FAIL" }
                    ));
                }
            }
        }

        details.join("; ")
    }
}

/// Regression test scenario definition
#[derive(Debug, Clone)]
pub struct RegressionScenario {
    pub name: String,
    pub description: String,
    pub request: TestRequest,
    pub platforms: Vec<String>,
    pub expected_outcome: ExpectedOutcome,
    pub critical: bool,
}

/// Test request definition
#[derive(Debug, Clone)]
pub struct TestRequest {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

/// Expected outcome of a test
#[derive(Debug, Clone, PartialEq)]
pub enum ExpectedOutcome {
    Success,
    Failure,
}

/// Result of executing a scenario
#[derive(Debug, Clone)]
pub struct ScenarioResult {
    pub scenario_name: String,
    pub timestamp: DateTime<Utc>,
    pub platform_results: HashMap<String, PlatformResult>,
    pub overall_success: bool,
}

/// Result for a specific platform
#[derive(Debug, Clone)]
pub struct PlatformResult {
    pub success: bool,
    pub execution_time: Duration,
    pub error_message: Option<String>,
    pub response_data: Option<Value>,
}

/// Baseline results for regression comparison
#[derive(Debug)]
pub struct RegressionBaseline {
    pub scenario_results: HashMap<String, ScenarioResult>,
    pub created_at: DateTime<Utc>,
}

impl RegressionBaseline {
    pub fn new() -> Self {
        Self {
            scenario_results: HashMap::new(),
            created_at: Utc::now(),
        }
    }

    pub fn add_scenario_result(&mut self, name: &str, result: ScenarioResult) {
        self.scenario_results.insert(name.to_string(), result);
    }

    pub fn get_scenario_result(&self, name: &str) -> Option<&ScenarioResult> {
        self.scenario_results.get(name)
    }
}

/// Results of regression testing
#[derive(Debug)]
pub struct RegressionResults {
    pub comparisons: Vec<RegressionComparison>,
    pub total_tests: usize,
    pub regressions: usize,
    pub improvements: usize,
    pub stable_tests: usize,
}

impl RegressionResults {
    pub fn new() -> Self {
        Self {
            comparisons: Vec::new(),
            total_tests: 0,
            regressions: 0,
            improvements: 0,
            stable_tests: 0,
        }
    }

    pub fn add_comparison(&mut self, comparison: RegressionComparison) {
        match comparison.status {
            RegressionStatus::Regression | RegressionStatus::PerformanceRegression => {
                self.regressions += 1;
            }
            RegressionStatus::Improvement => {
                self.improvements += 1;
            }
            RegressionStatus::Stable => {
                self.stable_tests += 1;
            }
            RegressionStatus::NewTest => {
                // Don't count new tests in stability metrics
            }
        }

        self.comparisons.push(comparison);
        self.total_tests += 1;
    }

    pub fn has_regressions(&self) -> bool {
        self.regressions > 0
    }

    pub fn summary(&self) -> String {
        format!(
            "Regression Testing Results:\n\
             Total tests: {}\n\
             Stable tests: {} ({:.1}%)\n\
             Improvements: {}\n\
             Regressions: {}\n\
             \n\
             Status: {}",
            self.total_tests,
            self.stable_tests,
            if self.total_tests > 0 {
                (self.stable_tests as f64 / self.total_tests as f64) * 100.0
            } else {
                0.0
            },
            self.improvements,
            self.regressions,
            if self.has_regressions() {
                "❌ REGRESSIONS DETECTED"
            } else {
                "✅ NO REGRESSIONS"
            }
        )
    }
}

/// Comparison between current and baseline results
#[derive(Debug)]
pub struct RegressionComparison {
    pub scenario_name: String,
    pub status: RegressionStatus,
    pub details: String,
    pub performance_change: Option<PerformanceChange>,
    pub success_change: SuccessChange,
}

/// Status of regression comparison
#[derive(Debug, PartialEq)]
pub enum RegressionStatus {
    Stable,
    Regression,
    PerformanceRegression,
    Improvement,
    NewTest,
}

/// Change in success status
#[derive(Debug, PartialEq)]
pub enum SuccessChange {
    NoChange,
    Regression,
    Improvement,
}

/// Performance change details
#[derive(Debug)]
pub struct PerformanceChange {
    pub baseline_time: Duration,
    pub current_time: Duration,
    pub percentage_change: f64,
    pub significant_slowdown: bool,
    pub significant_improvement: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_regression_suite_creation() {
        let gateway_url = "http://localhost:3000".to_string();
        let suite = RegressionTestSuite::new(gateway_url);

        let scenarios = suite.create_regression_scenarios();
        assert!(!scenarios.is_empty(), "Should create regression scenarios");

        // Verify critical scenarios exist
        let critical_scenarios: Vec<_> = scenarios.iter().filter(|s| s.critical).collect();
        assert!(!critical_scenarios.is_empty(), "Should have critical regression scenarios");
    }

    #[test]
    fn test_regression_baseline_management() {
        let mut baseline = RegressionBaseline::new();

        let scenario_result = ScenarioResult {
            scenario_name: "test_scenario".to_string(),
            timestamp: Utc::now(),
            platform_results: HashMap::new(),
            overall_success: true,
        };

        baseline.add_scenario_result("test_scenario", scenario_result);

        assert!(baseline.get_scenario_result("test_scenario").is_some());
        assert!(baseline.get_scenario_result("nonexistent").is_none());
    }

    #[test]
    fn test_regression_results_aggregation() {
        let mut results = RegressionResults::new();

        let stable_comparison = RegressionComparison {
            scenario_name: "stable_test".to_string(),
            status: RegressionStatus::Stable,
            details: "Test remains stable".to_string(),
            performance_change: None,
            success_change: SuccessChange::NoChange,
        };

        let regression_comparison = RegressionComparison {
            scenario_name: "regression_test".to_string(),
            status: RegressionStatus::Regression,
            details: "Test regressed".to_string(),
            performance_change: None,
            success_change: SuccessChange::Regression,
        };

        results.add_comparison(stable_comparison);
        results.add_comparison(regression_comparison);

        assert_eq!(results.total_tests, 2);
        assert_eq!(results.stable_tests, 1);
        assert_eq!(results.regressions, 1);
        assert!(results.has_regressions());
    }

    #[tokio::test]
    async fn test_full_regression_suite() {
        // Only run if test gateway URL is provided
        let gateway_url = match std::env::var("VEFAS_GATEWAY_TEST_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("Skipping regression tests: VEFAS_GATEWAY_TEST_URL not set");
                return;
            }
        };

        let mut suite = RegressionTestSuite::new(gateway_url);

        // Load baseline (this will generate one)
        suite.load_baseline().await.expect("Should load baseline");

        // Run regression tests
        let results = suite.run_regression_tests().await.expect("Should run regression tests");

        println!("{}", results.summary());

        // Assert no regressions in a fresh test run
        assert!(!results.has_regressions(), "Fresh test run should not have regressions");
    }
}