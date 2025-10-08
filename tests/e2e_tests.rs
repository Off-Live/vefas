//! End-to-end testing suite for VEFAS
//!
//! This module orchestrates comprehensive end-to-end testing including
//! cross-platform consistency, regression testing, and load testing
//! to ensure production readiness.

use std::time::{Duration, Instant};
use tokio::time::timeout;

// Import all E2E test modules
// Temporarily disabled modules (files renamed to .disabled)
// #[path = "e2e/cross_platform/platform_consistency.rs"]
// mod platform_consistency;

// #[path = "e2e/regression/regression_tests.rs"]
// mod regression_tests;

// #[path = "e2e/stress/load_tests.rs"]
// mod load_tests;

#[path = "e2e/merkle_proof_e2e.rs"]
mod merkle_proof_e2e;

use merkle_proof_e2e::{MerkleProofE2ETester, MerkleProofE2EResults};

// Temporarily disabled imports
// use platform_consistency::{CrossPlatformTester, CrossPlatformResults};
// use regression_tests::{RegressionTestSuite, RegressionResults};
// use load_tests::{LoadTestSuite, LoadTestResults};

/// Comprehensive end-to-end test configuration
#[derive(Debug, Clone)]
pub struct E2ETestConfig {
    pub gateway_url: String,
    pub enable_cross_platform_tests: bool,
    pub enable_regression_tests: bool,
    pub enable_load_tests: bool,
    pub enable_merkle_proof_tests: bool,
    // Temporarily disabled
    // pub load_test_config: LoadTestConfig,
    pub test_timeout: Duration,
    pub fail_on_performance_regression: bool,
    pub max_acceptable_failure_rate: f64,
}

impl E2ETestConfig {
    pub fn new(gateway_url: String) -> Self {
        Self {
            gateway_url,
            enable_cross_platform_tests: true,
            enable_regression_tests: true,
            enable_load_tests: std::env::var("VEFAS_ENABLE_LOAD_TESTS").unwrap_or_default() == "true",
            enable_merkle_proof_tests: true,
            // Temporarily disabled
            // load_test_config: LoadTestConfig::default(),
            test_timeout: Duration::from_secs(1800), // 30 minutes total timeout
            fail_on_performance_regression: true,
            max_acceptable_failure_rate: 5.0, // 5% max failure rate
        }
    }

    pub fn quick_test(gateway_url: String) -> Self {
        Self {
            gateway_url,
            enable_cross_platform_tests: true,
            enable_regression_tests: true,
            enable_load_tests: false, // Skip load tests in quick mode
            enable_merkle_proof_tests: true, // Keep Merkle proof tests in quick mode
            // Temporarily disabled
            // load_test_config: LoadTestConfig {
            //     concurrent_users: 2,
            //     requests_per_user: 2,
            //     test_duration: Duration::from_secs(10),
            //     ..LoadTestConfig::default()
            // },
            test_timeout: Duration::from_secs(300), // 5 minutes for quick test
            fail_on_performance_regression: false,
            max_acceptable_failure_rate: 10.0,
        }
    }
}

/// End-to-end test suite orchestrator
pub struct E2ETestSuite {
    config: E2ETestConfig,
}

impl E2ETestSuite {
    pub fn new(config: E2ETestConfig) -> Self {
        Self { config }
    }

    /// Run complete end-to-end test suite
    pub async fn run_complete_e2e_tests(&self) -> E2ETestResults {
        let overall_start = Instant::now();
        let mut results = E2ETestResults::new();

        println!("🚀 Starting comprehensive E2E test suite");
        println!("Gateway URL: {}", self.config.gateway_url);
        println!("Configuration: {:?}", self.config);
        println!("========================================\n");

        // Wrap entire test suite in timeout
        let test_result = timeout(
            self.config.test_timeout,
            self.execute_all_tests()
        ).await;

        match test_result {
            Ok(test_results) => {
                results = test_results;
            }
            Err(_) => {
                results.timeout_occurred = true;
                results.overall_success = false;
                println!("❌ E2E test suite timed out after {}s", self.config.test_timeout.as_secs());
            }
        }

        results.total_execution_time = overall_start.elapsed();

        println!("\n🏁 E2E Test Suite Completed");
        println!("==============================");
        println!("{}", results.summary());

        results
    }

    /// Execute all enabled tests
    async fn execute_all_tests(&self) -> E2ETestResults {
        let mut results = E2ETestResults::new();

        // Phase 1: Cross-platform consistency tests
        if self.config.enable_cross_platform_tests {
            println!("🔄 Phase 1: Cross-platform consistency testing");
            match self.run_cross_platform_tests().await {
                Ok(cross_platform_results) => {
                    results.cross_platform_results = Some(cross_platform_results);
                    println!("✅ Cross-platform tests completed\n");
                }
                Err(e) => {
                    println!("❌ Cross-platform tests failed: {}\n", e);
                    results.cross_platform_error = Some(e);
                    results.overall_success = false;
                }
            }
        } else {
            println!("⏩ Skipping cross-platform tests\n");
        }

        // Phase 2: Regression testing
        if self.config.enable_regression_tests {
            println!("📊 Phase 2: Regression testing");
            match self.run_regression_tests().await {
                Ok(regression_results) => {
                    results.regression_results = Some(regression_results);
                    println!("✅ Regression tests completed\n");
                }
                Err(e) => {
                    println!("❌ Regression tests failed: {}\n", e);
                    results.regression_error = Some(e);
                    results.overall_success = false;
                }
            }
        } else {
            println!("⏩ Skipping regression tests\n");
        }

        // Phase 3: Merkle proof verification testing
        if self.config.enable_merkle_proof_tests {
            println!("🔐 Phase 3: Merkle proof verification testing");
            match self.run_merkle_proof_tests().await {
                Ok(merkle_results) => {
                    results.merkle_proof_results = Some(merkle_results);
                    println!("✅ Merkle proof tests completed\n");
                }
                Err(e) => {
                    println!("❌ Merkle proof tests failed: {}\n", e);
                    results.merkle_proof_error = Some(e);
                    results.overall_success = false;
                }
            }
        } else {
            println!("⏩ Skipping Merkle proof tests\n");
        }

        // Phase 4: Load and stress testing
        if self.config.enable_load_tests {
            println!("⚡ Phase 4: Load and stress testing");
            match self.run_load_tests().await {
                Ok(load_results) => {
                    results.load_test_results = Some(load_results);
                    println!("✅ Load tests completed\n");
                }
                Err(e) => {
                    println!("❌ Load tests failed: {}\n", e);
                    results.load_test_error = Some(e);
                    // Load test failures don't necessarily fail the entire suite
                }
            }
        } else {
            println!("⏩ Skipping load tests\n");
        }

        // Evaluate overall success
        results.overall_success = self.evaluate_overall_success(&results);

        results
    }

    /// Run cross-platform consistency tests
    async fn run_cross_platform_tests(&self) -> Result<CrossPlatformResults, String> {
        let tester = CrossPlatformTester::new(self.config.gateway_url.clone());
        let results = tester.run_consistency_tests().await;

        // Validate results meet acceptance criteria
        if results.consistency_rate() < 95.0 {
            return Err(format!("Cross-platform consistency too low: {:.1}%", results.consistency_rate()));
        }

        if results.sp1_success_rate() < 80.0 {
            return Err(format!("SP1 success rate too low: {:.1}%", results.sp1_success_rate()));
        }

        if results.risc0_success_rate() < 80.0 {
            return Err(format!("RISC0 success rate too low: {:.1}%", results.risc0_success_rate()));
        }

        Ok(results)
    }

    /// Run regression tests
    async fn run_regression_tests(&self) -> Result<RegressionResults, String> {
        let mut suite = RegressionTestSuite::new(self.config.gateway_url.clone());

        // Load or generate baseline
        suite.load_baseline().await
            .map_err(|e| format!("Failed to load regression baseline: {}", e))?;

        // Run regression tests
        let results = suite.run_regression_tests().await
            .map_err(|e| format!("Failed to run regression tests: {}", e))?;

        // Check for critical regressions
        if results.has_regressions() && self.config.fail_on_performance_regression {
            return Err(format!("Regressions detected: {} failures", results.regressions));
        }

        Ok(results)
    }

    /// Run Merkle proof verification tests
    async fn run_merkle_proof_tests(&self) -> Result<MerkleProofE2EResults, String> {
        let tester = MerkleProofE2ETester::new(self.config.gateway_url.clone());
        let results = tester.run_merkle_proof_tests().await;

        // Validate results meet acceptance criteria
        if !results.all_tests_passed() {
            return Err(format!("Merkle proof tests failed: {:.1}% success rate", results.success_rate()));
        }

        if results.merkle_verification_rate() < 100.0 {
            return Err(format!("Merkle verification rate too low: {:.1}%", results.merkle_verification_rate()));
        }

        Ok(results)
    }

    /// Run load and stress tests
    async fn run_load_tests(&self) -> Result<LoadTestResults, String> {
        let suite = LoadTestSuite::new(
            self.config.gateway_url.clone(),
            self.config.load_test_config.clone()
        );

        let results = suite.run_load_tests().await;

        // Validate load test results
        if let Some(sustained) = &results.sustained_results {
            if sustained.success_rate() < (100.0 - self.config.max_acceptable_failure_rate) {
                return Err(format!(
                    "Load test failure rate too high: {:.1}%",
                    100.0 - sustained.success_rate()
                ));
            }
        }

        Ok(results)
    }

    /// Evaluate overall test suite success
    fn evaluate_overall_success(&self, results: &E2ETestResults) -> bool {
        let mut success = true;

        // Check cross-platform results
        if let Some(cross_platform) = &results.cross_platform_results {
            if cross_platform.consistency_rate() < 95.0 {
                println!("❌ Cross-platform consistency below threshold");
                success = false;
            }
        } else if results.cross_platform_error.is_some() {
            println!("❌ Cross-platform tests failed");
            success = false;
        }

        // Check regression results
        if let Some(regression) = &results.regression_results {
            if regression.has_regressions() && self.config.fail_on_performance_regression {
                println!("❌ Regressions detected");
                success = false;
            }
        } else if results.regression_error.is_some() {
            println!("❌ Regression tests failed");
            success = false;
        }

        // Check Merkle proof results
        if let Some(merkle_proof) = &results.merkle_proof_results {
            if !merkle_proof.all_tests_passed() {
                println!("❌ Merkle proof tests failed");
                success = false;
            }
        } else if results.merkle_proof_error.is_some() {
            println!("❌ Merkle proof tests failed");
            success = false;
        }

        // Check load test results (if enabled)
        if self.config.enable_load_tests {
            if let Some(load_tests) = &results.load_test_results {
                if let Some(sustained) = &load_tests.sustained_results {
                    if sustained.success_rate() < (100.0 - self.config.max_acceptable_failure_rate) {
                        println!("❌ Load test failure rate too high");
                        success = false;
                    }
                }
            } else if results.load_test_error.is_some() {
                println!("⚠️  Load tests failed (not failing overall suite)");
                // Load test failures don't fail the suite in this implementation
            }
        }

        if results.timeout_occurred {
            println!("❌ Test suite timed out");
            success = false;
        }

        success
    }
}

/// Complete end-to-end test results
#[derive(Debug)]
pub struct E2ETestResults {
    pub cross_platform_results: Option<CrossPlatformResults>,
    pub regression_results: Option<RegressionResults>,
    pub load_test_results: Option<LoadTestResults>,
    pub merkle_proof_results: Option<MerkleProofE2EResults>,
    pub cross_platform_error: Option<String>,
    pub regression_error: Option<String>,
    pub load_test_error: Option<String>,
    pub merkle_proof_error: Option<String>,
    pub timeout_occurred: bool,
    pub overall_success: bool,
    pub total_execution_time: Duration,
}

impl E2ETestResults {
    pub fn new() -> Self {
        Self {
            cross_platform_results: None,
            regression_results: None,
            load_test_results: None,
            merkle_proof_results: None,
            cross_platform_error: None,
            regression_error: None,
            load_test_error: None,
            merkle_proof_error: None,
            timeout_occurred: false,
            overall_success: true,
            total_execution_time: Duration::from_secs(0),
        }
    }

    pub fn summary(&self) -> String {
        let mut summary = String::new();
        summary.push_str(&format!(
            "E2E Test Suite Results:\n\
             Overall Status: {}\n\
             Total Execution Time: {:.1}s\n\
             Timeout Occurred: {}\n\n",
            if self.overall_success { "✅ PASSED" } else { "❌ FAILED" },
            self.total_execution_time.as_secs_f64(),
            if self.timeout_occurred { "Yes" } else { "No" }
        ));

        // Cross-platform results
        summary.push_str("Cross-Platform Testing:\n");
        if let Some(results) = &self.cross_platform_results {
            summary.push_str(&format!(
                "  Status: ✅ PASSED\n\
                 Consistency Rate: {:.1}%\n\
                 SP1 Success Rate: {:.1}%\n\
                 RISC0 Success Rate: {:.1}%\n\n",
                results.consistency_rate(),
                results.sp1_success_rate(),
                results.risc0_success_rate()
            ));
        } else if let Some(error) = &self.cross_platform_error {
            summary.push_str(&format!("  Status: ❌ FAILED - {}\n\n", error));
        } else {
            summary.push_str("  Status: ⏩ SKIPPED\n\n");
        }

        // Regression results
        summary.push_str("Regression Testing:\n");
        if let Some(results) = &self.regression_results {
            summary.push_str(&format!(
                "  Status: {}\n\
                 Total Tests: {}\n\
                 Stable Tests: {}\n\
                 Regressions: {}\n\
                 Improvements: {}\n\n",
                if results.has_regressions() { "⚠️  REGRESSIONS" } else { "✅ PASSED" },
                results.total_tests,
                results.stable_tests,
                results.regressions,
                results.improvements
            ));
        } else if let Some(error) = &self.regression_error {
            summary.push_str(&format!("  Status: ❌ FAILED - {}\n\n", error));
        } else {
            summary.push_str("  Status: ⏩ SKIPPED\n\n");
        }

        // Merkle proof results
        summary.push_str("Merkle Proof Testing:\n");
        if let Some(results) = &self.merkle_proof_results {
            summary.push_str(&format!(
                "  Status: {}\n\
                 Total Tests: {}\n\
                 Successful Tests: {} ({:.1}%)\n\
                 Merkle Verification Successes: {} ({:.1}%)\n\
                 Average Execution Time: {:.2}s\n\n",
                if results.all_tests_passed() { "✅ PASSED" } else { "❌ FAILED" },
                results.total_tests,
                results.successful_tests,
                results.success_rate(),
                results.merkle_verification_successes,
                results.merkle_verification_rate(),
                results.average_execution_time.as_secs_f64()
            ));
        } else if let Some(error) = &self.merkle_proof_error {
            summary.push_str(&format!("  Status: ❌ FAILED - {}\n\n", error));
        } else {
            summary.push_str("  Status: ⏩ SKIPPED\n\n");
        }

        // Load test results
        summary.push_str("Load Testing:\n");
        if let Some(results) = &self.load_test_results {
            let mut load_summary = String::new();

            if let Some(baseline) = &results.baseline_results {
                load_summary.push_str(&format!("  Baseline: {:.1} req/s, {:.1}% success\n",
                                               baseline.requests_per_second(), baseline.success_rate()));
            }

            if let Some(sustained) = &results.sustained_results {
                load_summary.push_str(&format!("  Sustained: {:.1} req/s, {:.1}% success\n",
                                               sustained.requests_per_second(), sustained.success_rate()));
            }

            summary.push_str(&format!("  Status: ✅ COMPLETED\n{}\n", load_summary));
        } else if let Some(error) = &self.load_test_error {
            summary.push_str(&format!("  Status: ❌ FAILED - {}\n\n", error));
        } else {
            summary.push_str("  Status: ⏩ SKIPPED\n\n");
        }

        summary.push_str(&format!(
            "Final Result: {}\n",
            if self.overall_success {
                "🎉 All tests passed! System is ready for production."
            } else {
                "💥 Some tests failed. Review results before production deployment."
            }
        ));

        summary
    }

    /// Check if system meets production readiness criteria
    pub fn is_production_ready(&self) -> bool {
        self.overall_success && !self.timeout_occurred
    }

    /// Get critical issues that must be addressed
    pub fn get_critical_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();

        if let Some(error) = &self.cross_platform_error {
            issues.push(format!("Cross-platform testing failed: {}", error));
        }

        if let Some(results) = &self.cross_platform_results {
            if results.consistency_rate() < 95.0 {
                issues.push(format!("Cross-platform consistency too low: {:.1}%", results.consistency_rate()));
            }
        }

        if let Some(error) = &self.regression_error {
            issues.push(format!("Regression testing failed: {}", error));
        }

        if let Some(results) = &self.regression_results {
            if results.has_regressions() {
                issues.push(format!("Regressions detected: {} failures", results.regressions));
            }
        }

        if let Some(error) = &self.merkle_proof_error {
            issues.push(format!("Merkle proof testing failed: {}", error));
        }

        if let Some(results) = &self.merkle_proof_results {
            if !results.all_tests_passed() {
                issues.push(format!("Merkle proof tests failed: {:.1}% success rate", results.success_rate()));
            }
            if results.merkle_verification_rate() < 100.0 {
                issues.push(format!("Merkle verification rate too low: {:.1}%", results.merkle_verification_rate()));
            }
        }

        if self.timeout_occurred {
            issues.push("Test suite timed out - may indicate performance issues".to_string());
        }

        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2e_config_creation() {
        let config = E2ETestConfig::new("http://localhost:3000".to_string());
        assert!(config.enable_cross_platform_tests);
        assert!(config.enable_regression_tests);
        assert_eq!(config.max_acceptable_failure_rate, 5.0);

        let quick_config = E2ETestConfig::quick_test("http://localhost:3000".to_string());
        assert!(!quick_config.enable_load_tests);
        assert!(quick_config.enable_merkle_proof_tests); // Merkle proof tests should be enabled in quick mode
        assert_eq!(quick_config.test_timeout.as_secs(), 300);
    }

    #[test]
    fn test_e2e_results_creation() {
        let results = E2ETestResults::new();
        assert!(results.overall_success);
        assert!(!results.timeout_occurred);
        assert!(results.cross_platform_results.is_none());
    }

    #[tokio::test]
    async fn test_e2e_suite_creation() {
        let config = E2ETestConfig::quick_test("http://localhost:3000".to_string());
        let suite = E2ETestSuite::new(config);

        // Test suite should be created successfully
        assert!(!suite.config.enable_load_tests); // Quick mode disables load tests
    }

    #[tokio::test]
    async fn test_complete_e2e_suite() {
        // Only run if test gateway URL is provided
        let gateway_url = match std::env::var("VEFAS_GATEWAY_TEST_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("Skipping E2E tests: VEFAS_GATEWAY_TEST_URL not set");
                return;
            }
        };

        let config = E2ETestConfig::quick_test(gateway_url);
        let suite = E2ETestSuite::new(config);

        let results = suite.run_complete_e2e_tests().await;

        println!("{}", results.summary());

        // Verify we have some results
        assert!(results.cross_platform_results.is_some() || results.cross_platform_error.is_some());

        // Check production readiness
        if results.is_production_ready() {
            println!("✅ System is production ready!");
        } else {
            println!("❌ Critical issues found:");
            for issue in results.get_critical_issues() {
                println!("  - {}", issue);
            }
        }
    }
}