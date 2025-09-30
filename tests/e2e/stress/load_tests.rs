//! Load and stress testing for VEFAS Gateway
//!
//! This module implements comprehensive load testing to validate
//! system performance under stress, identify bottlenecks, and
//! ensure the system can handle production workloads.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use reqwest::Client;
use serde_json::{json, Value};
use tokio::time::{sleep, timeout};
use futures::future::join_all;
use tokio::sync::Semaphore;

/// Load testing configuration
#[derive(Debug, Clone)]
pub struct LoadTestConfig {
    pub concurrent_users: usize,
    pub requests_per_user: usize,
    pub ramp_up_duration: Duration,
    pub test_duration: Duration,
    pub think_time: Duration,
    pub timeout_per_request: Duration,
}

impl Default for LoadTestConfig {
    fn default() -> Self {
        Self {
            concurrent_users: 10,
            requests_per_user: 5,
            ramp_up_duration: Duration::from_secs(10),
            test_duration: Duration::from_secs(60),
            think_time: Duration::from_millis(100),
            timeout_per_request: Duration::from_secs(30),
        }
    }
}

/// Load test scenario
#[derive(Debug, Clone)]
pub struct LoadTestScenario {
    pub name: String,
    pub description: String,
    pub weight: f64, // Probability of this scenario being selected
    pub request_template: RequestTemplate,
}

/// Request template for load testing
#[derive(Debug, Clone)]
pub struct RequestTemplate {
    pub method: String,
    pub url: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub proof_platform: String,
}

/// Load testing suite
pub struct LoadTestSuite {
    gateway_url: String,
    client: Client,
    config: LoadTestConfig,
    scenarios: Vec<LoadTestScenario>,
}

impl LoadTestSuite {
    pub fn new(gateway_url: String, config: LoadTestConfig) -> Self {
        let client = Client::builder()
            .timeout(config.timeout_per_request)
            .pool_max_idle_per_host(50) // Increase connection pool
            .build()
            .expect("Failed to create HTTP client");

        Self {
            gateway_url,
            client,
            config,
            scenarios: Self::create_load_test_scenarios(),
        }
    }

    /// Create load test scenarios with different characteristics
    fn create_load_test_scenarios() -> Vec<LoadTestScenario> {
        vec![
            LoadTestScenario {
                name: "light_get_request".to_string(),
                description: "Light GET request for basic functionality".to_string(),
                weight: 0.4, // 40% of requests
                request_template: RequestTemplate {
                    method: "GET".to_string(),
                    url: "https://httpbin.org/get".to_string(),
                    headers: HashMap::new(),
                    body: None,
                    proof_platform: "sp1".to_string(),
                },
            },
            LoadTestScenario {
                name: "medium_post_request".to_string(),
                description: "Medium POST request with JSON payload".to_string(),
                weight: 0.3, // 30% of requests
                request_template: RequestTemplate {
                    method: "POST".to_string(),
                    url: "https://httpbin.org/post".to_string(),
                    headers: vec![
                        ("Content-Type".to_string(), "application/json".to_string()),
                    ].into_iter().collect(),
                    body: Some(json!({
                        "user_id": 12345,
                        "data": "test data for load testing",
                        "metadata": {
                            "test_type": "load_test",
                            "timestamp": 1234567890
                        }
                    }).to_string()),
                    proof_platform: "sp1".to_string(),
                },
            },
            LoadTestScenario {
                name: "heavy_risc0_request".to_string(),
                description: "Heavy request using RISC0 platform".to_string(),
                weight: 0.2, // 20% of requests
                request_template: RequestTemplate {
                    method: "POST".to_string(),
                    url: "https://httpbin.org/post".to_string(),
                    headers: vec![
                        ("Content-Type".to_string(), "application/json".to_string()),
                        ("User-Agent".to_string(), "VEFAS-LoadTest/1.0".to_string()),
                    ].into_iter().collect(),
                    body: Some(json!({
                        "large_data": "x".repeat(500), // Larger payload
                        "array_data": (0..50).collect::<Vec<i32>>(),
                        "complex_nested": {
                            "level1": {
                                "level2": {
                                    "level3": "deep nesting test"
                                }
                            }
                        }
                    }).to_string()),
                    proof_platform: "risc0".to_string(),
                },
            },
            LoadTestScenario {
                name: "authenticated_request".to_string(),
                description: "Request with authentication headers".to_string(),
                weight: 0.1, // 10% of requests
                request_template: RequestTemplate {
                    method: "GET".to_string(),
                    url: "https://httpbin.org/bearer".to_string(),
                    headers: vec![
                        ("Authorization".to_string(), "Bearer load-test-token".to_string()),
                    ].into_iter().collect(),
                    body: None,
                    proof_platform: "sp1".to_string(),
                },
            },
        ]
    }

    /// Run comprehensive load tests
    pub async fn run_load_tests(&self) -> LoadTestResults {
        println!("🚀 Starting load tests...");
        println!("Configuration: {} users, {} requests/user, {}s duration",
                 self.config.concurrent_users,
                 self.config.requests_per_user,
                 self.config.test_duration.as_secs());

        let mut results = LoadTestResults::new();

        // Phase 1: Baseline performance test
        println!("📊 Phase 1: Baseline performance");
        let baseline_results = self.run_baseline_test().await;
        results.baseline_results = Some(baseline_results);

        // Phase 2: Ramp-up load test
        println!("📈 Phase 2: Ramp-up load test");
        let rampup_results = self.run_rampup_test().await;
        results.rampup_results = Some(rampup_results);

        // Phase 3: Sustained load test
        println!("⚡ Phase 3: Sustained load test");
        let sustained_results = self.run_sustained_load_test().await;
        results.sustained_results = Some(sustained_results);

        // Phase 4: Spike test
        println!("📊 Phase 4: Spike test");
        let spike_results = self.run_spike_test().await;
        results.spike_results = Some(spike_results);

        // Phase 5: Stress test (find breaking point)
        println!("🔥 Phase 5: Stress test");
        let stress_results = self.run_stress_test().await;
        results.stress_results = Some(stress_results);

        println!("✅ Load tests completed");
        results
    }

    /// Run baseline performance test with single user
    async fn run_baseline_test(&self) -> PhaseResults {
        let start_time = Instant::now();
        let stats = Arc::new(RequestStats::new());

        // Single user making sequential requests
        for i in 0..self.config.requests_per_user {
            let scenario = self.select_scenario();
            let result = self.execute_request(&scenario.request_template, &stats).await;

            if let Err(e) = result {
                println!("Baseline request {} failed: {}", i, e);
            }

            // Small delay between requests
            sleep(self.config.think_time).await;
        }

        PhaseResults {
            phase_name: "Baseline".to_string(),
            duration: start_time.elapsed(),
            total_requests: self.config.requests_per_user,
            successful_requests: stats.successful_requests.load(Ordering::Relaxed),
            failed_requests: stats.failed_requests.load(Ordering::Relaxed),
            total_response_time: Duration::from_millis(stats.total_response_time_ms.load(Ordering::Relaxed)),
            max_response_time: Duration::from_millis(stats.max_response_time_ms.load(Ordering::Relaxed)),
            min_response_time: Duration::from_millis(stats.min_response_time_ms.load(Ordering::Relaxed)),
            errors: stats.get_errors(),
            concurrent_users: 1,
        }
    }

    /// Run ramp-up test gradually increasing load
    async fn run_rampup_test(&self) -> PhaseResults {
        let start_time = Instant::now();
        let stats = Arc::new(RequestStats::new());
        let mut handles = vec![];

        let ramp_step = self.config.ramp_up_duration / self.config.concurrent_users as u32;

        for user_id in 0..self.config.concurrent_users {
            let delay = ramp_step * user_id as u32;
            let stats_clone = Arc::clone(&stats);
            let scenarios = self.scenarios.clone();
            let client = self.client.clone();
            let gateway_url = self.gateway_url.clone();
            let config = self.config.clone();

            let handle = tokio::spawn(async move {
                sleep(delay).await;

                for _ in 0..config.requests_per_user {
                    let scenario = Self::select_scenario_from_list(&scenarios);
                    let result = Self::execute_request_static(
                        &scenario.request_template,
                        &stats_clone,
                        &client,
                        &gateway_url,
                    ).await;

                    if let Err(e) = result {
                        stats_clone.add_error(format!("User {}: {}", user_id, e));
                    }

                    sleep(config.think_time).await;
                }
            });

            handles.push(handle);
        }

        join_all(handles).await;

        PhaseResults {
            phase_name: "Ramp-up".to_string(),
            duration: start_time.elapsed(),
            total_requests: self.config.concurrent_users * self.config.requests_per_user,
            successful_requests: stats.successful_requests.load(Ordering::Relaxed),
            failed_requests: stats.failed_requests.load(Ordering::Relaxed),
            total_response_time: Duration::from_millis(stats.total_response_time_ms.load(Ordering::Relaxed)),
            max_response_time: Duration::from_millis(stats.max_response_time_ms.load(Ordering::Relaxed)),
            min_response_time: Duration::from_millis(stats.min_response_time_ms.load(Ordering::Relaxed)),
            errors: stats.get_errors(),
            concurrent_users: self.config.concurrent_users,
        }
    }

    /// Run sustained load test
    async fn run_sustained_load_test(&self) -> PhaseResults {
        let start_time = Instant::now();
        let stats = Arc::new(RequestStats::new());
        let semaphore = Arc::new(Semaphore::new(self.config.concurrent_users));

        let end_time = start_time + self.config.test_duration;
        let mut request_count = 0;

        while Instant::now() < end_time {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let stats_clone = Arc::clone(&stats);
            let scenarios = self.scenarios.clone();
            let client = self.client.clone();
            let gateway_url = self.gateway_url.clone();
            let think_time = self.config.think_time;

            request_count += 1;

            tokio::spawn(async move {
                let _permit = permit; // Hold permit until task completes

                let scenario = Self::select_scenario_from_list(&scenarios);
                let result = Self::execute_request_static(
                    &scenario.request_template,
                    &stats_clone,
                    &client,
                    &gateway_url,
                ).await;

                if let Err(e) = result {
                    stats_clone.add_error(format!("Sustained load: {}", e));
                }

                sleep(think_time).await;
            });

            // Control request rate
            sleep(Duration::from_millis(10)).await;
        }

        // Wait for all requests to complete
        let _all_permits = semaphore.acquire_many(self.config.concurrent_users as u32).await.unwrap();

        PhaseResults {
            phase_name: "Sustained Load".to_string(),
            duration: start_time.elapsed(),
            total_requests: request_count,
            successful_requests: stats.successful_requests.load(Ordering::Relaxed),
            failed_requests: stats.failed_requests.load(Ordering::Relaxed),
            total_response_time: Duration::from_millis(stats.total_response_time_ms.load(Ordering::Relaxed)),
            max_response_time: Duration::from_millis(stats.max_response_time_ms.load(Ordering::Relaxed)),
            min_response_time: Duration::from_millis(stats.min_response_time_ms.load(Ordering::Relaxed)),
            errors: stats.get_errors(),
            concurrent_users: self.config.concurrent_users,
        }
    }

    /// Run spike test with sudden load increase
    async fn run_spike_test(&self) -> PhaseResults {
        let start_time = Instant::now();
        let stats = Arc::new(RequestStats::new());

        // Sudden spike to 3x normal load
        let spike_users = self.config.concurrent_users * 3;
        let mut handles = vec![];

        for user_id in 0..spike_users {
            let stats_clone = Arc::clone(&stats);
            let scenarios = self.scenarios.clone();
            let client = self.client.clone();
            let gateway_url = self.gateway_url.clone();
            let config = self.config.clone();

            let handle = tokio::spawn(async move {
                // Shorter burst - only 3 requests per user
                for _ in 0..3 {
                    let scenario = Self::select_scenario_from_list(&scenarios);
                    let result = Self::execute_request_static(
                        &scenario.request_template,
                        &stats_clone,
                        &client,
                        &gateway_url,
                    ).await;

                    if let Err(e) = result {
                        stats_clone.add_error(format!("Spike user {}: {}", user_id, e));
                    }

                    sleep(config.think_time / 2).await; // Faster requests during spike
                }
            });

            handles.push(handle);
        }

        join_all(handles).await;

        PhaseResults {
            phase_name: "Spike Test".to_string(),
            duration: start_time.elapsed(),
            total_requests: spike_users * 3,
            successful_requests: stats.successful_requests.load(Ordering::Relaxed),
            failed_requests: stats.failed_requests.load(Ordering::Relaxed),
            total_response_time: Duration::from_millis(stats.total_response_time_ms.load(Ordering::Relaxed)),
            max_response_time: Duration::from_millis(stats.max_response_time_ms.load(Ordering::Relaxed)),
            min_response_time: Duration::from_millis(stats.min_response_time_ms.load(Ordering::Relaxed)),
            errors: stats.get_errors(),
            concurrent_users: spike_users,
        }
    }

    /// Run stress test to find breaking point
    async fn run_stress_test(&self) -> PhaseResults {
        let start_time = Instant::now();
        let stats = Arc::new(RequestStats::new());

        // Gradually increase load until failure rate becomes unacceptable
        let mut current_users = self.config.concurrent_users;
        let max_users = self.config.concurrent_users * 10;
        let step_size = self.config.concurrent_users;

        while current_users <= max_users {
            println!("Testing with {} concurrent users...", current_users);

            let step_stats = Arc::new(RequestStats::new());
            let mut handles = vec![];

            for user_id in 0..current_users {
                let step_stats_clone = Arc::clone(&step_stats);
                let scenarios = self.scenarios.clone();
                let client = self.client.clone();
                let gateway_url = self.gateway_url.clone();

                let handle = tokio::spawn(async move {
                    let scenario = Self::select_scenario_from_list(&scenarios);
                    let result = Self::execute_request_static(
                        &scenario.request_template,
                        &step_stats_clone,
                        &client,
                        &gateway_url,
                    ).await;

                    if let Err(e) = result {
                        step_stats_clone.add_error(format!("Stress user {}: {}", user_id, e));
                    }
                });

                handles.push(handle);
            }

            join_all(handles).await;

            // Aggregate stats
            stats.successful_requests.fetch_add(
                step_stats.successful_requests.load(Ordering::Relaxed),
                Ordering::Relaxed
            );
            stats.failed_requests.fetch_add(
                step_stats.failed_requests.load(Ordering::Relaxed),
                Ordering::Relaxed
            );

            // Check failure rate
            let total = step_stats.successful_requests.load(Ordering::Relaxed) +
                       step_stats.failed_requests.load(Ordering::Relaxed);
            let failure_rate = if total > 0 {
                (step_stats.failed_requests.load(Ordering::Relaxed) as f64 / total as f64) * 100.0
            } else {
                0.0
            };

            println!("Failure rate at {} users: {:.1}%", current_users, failure_rate);

            // Break if failure rate is too high (>20%)
            if failure_rate > 20.0 {
                println!("Breaking point reached at {} users", current_users);
                break;
            }

            current_users += step_size;
            sleep(Duration::from_secs(2)).await; // Brief pause between stress levels
        }

        PhaseResults {
            phase_name: "Stress Test".to_string(),
            duration: start_time.elapsed(),
            total_requests: stats.successful_requests.load(Ordering::Relaxed) +
                          stats.failed_requests.load(Ordering::Relaxed),
            successful_requests: stats.successful_requests.load(Ordering::Relaxed),
            failed_requests: stats.failed_requests.load(Ordering::Relaxed),
            total_response_time: Duration::from_millis(stats.total_response_time_ms.load(Ordering::Relaxed)),
            max_response_time: Duration::from_millis(stats.max_response_time_ms.load(Ordering::Relaxed)),
            min_response_time: Duration::from_millis(stats.min_response_time_ms.load(Ordering::Relaxed)),
            errors: stats.get_errors(),
            concurrent_users: current_users,
        }
    }

    /// Select a scenario based on weights
    fn select_scenario(&self) -> &LoadTestScenario {
        Self::select_scenario_from_list(&self.scenarios)
    }

    fn select_scenario_from_list(scenarios: &[LoadTestScenario]) -> &LoadTestScenario {
        // Simple weighted selection
        let total_weight: f64 = scenarios.iter().map(|s| s.weight).sum();
        let mut random_value = fastrand::f64() * total_weight;

        for scenario in scenarios {
            random_value -= scenario.weight;
            if random_value <= 0.0 {
                return scenario;
            }
        }

        // Fallback to first scenario
        &scenarios[0]
    }

    /// Execute a single request and update statistics
    async fn execute_request(
        &self,
        template: &RequestTemplate,
        stats: &RequestStats,
    ) -> Result<(), String> {
        Self::execute_request_static(template, stats, &self.client, &self.gateway_url).await
    }

    /// Static version of execute_request for use in async tasks
    async fn execute_request_static(
        template: &RequestTemplate,
        stats: &RequestStats,
        client: &Client,
        gateway_url: &str,
    ) -> Result<(), String> {
        let payload = json!({
            "method": template.method,
            "url": template.url,
            "headers": template.headers,
            "body": template.body,
            "proof_platform": template.proof_platform,
            "timeout_ms": 30000
        });

        let start_time = Instant::now();

        let result = timeout(
            Duration::from_secs(60),
            client
                .post(&format!("{}/api/v1/requests", gateway_url))
                .json(&payload)
                .send()
        ).await;

        let response_time = start_time.elapsed();

        match result {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    stats.record_success(response_time);
                    Ok(())
                } else {
                    stats.record_failure(response_time);
                    Err(format!("HTTP {}", response.status()))
                }
            }
            Ok(Err(e)) => {
                stats.record_failure(response_time);
                Err(format!("Request error: {}", e))
            }
            Err(_) => {
                stats.record_failure(response_time);
                Err("Request timeout".to_string())
            }
        }
    }
}

/// Request statistics tracking
#[derive(Debug)]
pub struct RequestStats {
    pub successful_requests: AtomicUsize,
    pub failed_requests: AtomicUsize,
    pub total_response_time_ms: AtomicUsize,
    pub max_response_time_ms: AtomicUsize,
    pub min_response_time_ms: AtomicUsize,
    pub errors: Arc<std::sync::Mutex<Vec<String>>>,
}

impl RequestStats {
    pub fn new() -> Self {
        Self {
            successful_requests: AtomicUsize::new(0),
            failed_requests: AtomicUsize::new(0),
            total_response_time_ms: AtomicUsize::new(0),
            max_response_time_ms: AtomicUsize::new(0),
            min_response_time_ms: AtomicUsize::new(usize::MAX),
            errors: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    pub fn record_success(&self, response_time: Duration) {
        self.successful_requests.fetch_add(1, Ordering::Relaxed);
        self.update_response_time(response_time);
    }

    pub fn record_failure(&self, response_time: Duration) {
        self.failed_requests.fetch_add(1, Ordering::Relaxed);
        self.update_response_time(response_time);
    }

    fn update_response_time(&self, response_time: Duration) {
        let ms = response_time.as_millis() as usize;

        self.total_response_time_ms.fetch_add(ms, Ordering::Relaxed);

        // Update max
        self.max_response_time_ms.fetch_max(ms, Ordering::Relaxed);

        // Update min
        self.min_response_time_ms.fetch_min(ms, Ordering::Relaxed);
    }

    pub fn add_error(&self, error: String) {
        if let Ok(mut errors) = self.errors.lock() {
            errors.push(error);
        }
    }

    pub fn get_errors(&self) -> Vec<String> {
        self.errors.lock().unwrap_or_default().clone()
    }
}

/// Results of a single test phase
#[derive(Debug)]
pub struct PhaseResults {
    pub phase_name: String,
    pub duration: Duration,
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub total_response_time: Duration,
    pub max_response_time: Duration,
    pub min_response_time: Duration,
    pub errors: Vec<String>,
    pub concurrent_users: usize,
}

impl PhaseResults {
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            (self.successful_requests as f64 / self.total_requests as f64) * 100.0
        }
    }

    pub fn average_response_time(&self) -> Duration {
        if self.successful_requests == 0 {
            Duration::from_secs(0)
        } else {
            self.total_response_time / self.successful_requests as u32
        }
    }

    pub fn requests_per_second(&self) -> f64 {
        if self.duration.as_secs_f64() == 0.0 {
            0.0
        } else {
            self.total_requests as f64 / self.duration.as_secs_f64()
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "{} Results:\n\
             Duration: {:.1}s\n\
             Total requests: {}\n\
             Success rate: {:.1}%\n\
             Requests/sec: {:.1}\n\
             Avg response time: {:.1}ms\n\
             Max response time: {:.1}ms\n\
             Min response time: {:.1}ms\n\
             Concurrent users: {}\n\
             Errors: {}",
            self.phase_name,
            self.duration.as_secs_f64(),
            self.total_requests,
            self.success_rate(),
            self.requests_per_second(),
            self.average_response_time().as_millis(),
            self.max_response_time.as_millis(),
            if self.min_response_time.as_millis() == usize::MAX as u128 { 0 } else { self.min_response_time.as_millis() },
            self.concurrent_users,
            self.errors.len()
        )
    }
}

/// Complete load test results
#[derive(Debug)]
pub struct LoadTestResults {
    pub baseline_results: Option<PhaseResults>,
    pub rampup_results: Option<PhaseResults>,
    pub sustained_results: Option<PhaseResults>,
    pub spike_results: Option<PhaseResults>,
    pub stress_results: Option<PhaseResults>,
}

impl LoadTestResults {
    pub fn new() -> Self {
        Self {
            baseline_results: None,
            rampup_results: None,
            sustained_results: None,
            spike_results: None,
            stress_results: None,
        }
    }

    pub fn summary(&self) -> String {
        let mut summary = String::from("Load Test Results Summary:\n");
        summary.push_str("==========================\n\n");

        if let Some(baseline) = &self.baseline_results {
            summary.push_str(&baseline.summary());
            summary.push_str("\n\n");
        }

        if let Some(rampup) = &self.rampup_results {
            summary.push_str(&rampup.summary());
            summary.push_str("\n\n");
        }

        if let Some(sustained) = &self.sustained_results {
            summary.push_str(&sustained.summary());
            summary.push_str("\n\n");
        }

        if let Some(spike) = &self.spike_results {
            summary.push_str(&spike.summary());
            summary.push_str("\n\n");
        }

        if let Some(stress) = &self.stress_results {
            summary.push_str(&stress.summary());
            summary.push_str("\n\n");
        }

        summary.push_str(&self.performance_analysis());

        summary
    }

    fn performance_analysis(&self) -> String {
        let mut analysis = String::from("Performance Analysis:\n");

        // Compare baseline vs sustained load
        if let (Some(baseline), Some(sustained)) = (&self.baseline_results, &self.sustained_results) {
            let baseline_avg = baseline.average_response_time();
            let sustained_avg = sustained.average_response_time();

            if sustained_avg > baseline_avg {
                let degradation = ((sustained_avg.as_millis() as f64 / baseline_avg.as_millis() as f64) - 1.0) * 100.0;
                analysis.push_str(&format!("- Response time degradation under load: {:.1}%\n", degradation));
            }

            let baseline_rps = baseline.requests_per_second();
            let sustained_rps = sustained.requests_per_second();
            analysis.push_str(&format!("- Throughput: {:.1} req/s (baseline) vs {:.1} req/s (sustained)\n", baseline_rps, sustained_rps));
        }

        // Check success rates
        let phases = [&self.baseline_results, &self.rampup_results, &self.sustained_results, &self.spike_results];
        let success_rates: Vec<f64> = phases.iter().filter_map(|p| p.as_ref().map(|r| r.success_rate())).collect();

        if let Some(min_success_rate) = success_rates.iter().min_by(|a, b| a.partial_cmp(b).unwrap()) {
            if *min_success_rate < 95.0 {
                analysis.push_str(&format!("- ⚠️  Minimum success rate: {:.1}% (below 95% threshold)\n", min_success_rate));
            } else {
                analysis.push_str(&format!("- ✅ Minimum success rate: {:.1}%\n", min_success_rate));
            }
        }

        analysis
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_test_config_default() {
        let config = LoadTestConfig::default();
        assert_eq!(config.concurrent_users, 10);
        assert_eq!(config.requests_per_user, 5);
    }

    #[test]
    fn test_scenario_selection() {
        let scenarios = LoadTestSuite::create_load_test_scenarios();
        assert!(!scenarios.is_empty());

        // Test weighted selection
        let selected = LoadTestSuite::select_scenario_from_list(&scenarios);
        assert!(!selected.name.is_empty());
    }

    #[test]
    fn test_request_stats() {
        let stats = RequestStats::new();

        stats.record_success(Duration::from_millis(100));
        stats.record_success(Duration::from_millis(200));
        stats.record_failure(Duration::from_millis(500));

        assert_eq!(stats.successful_requests.load(Ordering::Relaxed), 2);
        assert_eq!(stats.failed_requests.load(Ordering::Relaxed), 1);
        assert_eq!(stats.max_response_time_ms.load(Ordering::Relaxed), 500);
    }

    #[test]
    fn test_phase_results_calculations() {
        let results = PhaseResults {
            phase_name: "Test".to_string(),
            duration: Duration::from_secs(10),
            total_requests: 100,
            successful_requests: 95,
            failed_requests: 5,
            total_response_time: Duration::from_millis(9500), // 95 successful requests
            max_response_time: Duration::from_millis(200),
            min_response_time: Duration::from_millis(50),
            errors: vec![],
            concurrent_users: 5,
        };

        assert_eq!(results.success_rate(), 95.0);
        assert_eq!(results.requests_per_second(), 10.0);
        assert_eq!(results.average_response_time(), Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_load_test_suite_creation() {
        let config = LoadTestConfig {
            concurrent_users: 2,
            requests_per_user: 1,
            ramp_up_duration: Duration::from_secs(1),
            test_duration: Duration::from_secs(5),
            think_time: Duration::from_millis(10),
            timeout_per_request: Duration::from_secs(10),
        };

        let gateway_url = "http://localhost:3000".to_string();
        let suite = LoadTestSuite::new(gateway_url, config);

        assert_eq!(suite.scenarios.len(), 4);
        assert!(!suite.scenarios.is_empty());
    }

    #[tokio::test]
    async fn test_full_load_test_suite() {
        // Only run if test gateway URL is provided
        let gateway_url = match std::env::var("VEFAS_GATEWAY_TEST_URL") {
            Ok(url) => url,
            Err(_) => {
                eprintln!("Skipping load tests: VEFAS_GATEWAY_TEST_URL not set");
                return;
            }
        };

        let config = LoadTestConfig {
            concurrent_users: 2,
            requests_per_user: 2,
            ramp_up_duration: Duration::from_secs(2),
            test_duration: Duration::from_secs(5),
            think_time: Duration::from_millis(100),
            timeout_per_request: Duration::from_secs(30),
        };

        let suite = LoadTestSuite::new(gateway_url, config);
        let results = suite.run_load_tests().await;

        println!("{}", results.summary());

        // Verify we have results for all phases
        assert!(results.baseline_results.is_some());
        assert!(results.rampup_results.is_some());
        assert!(results.sustained_results.is_some());
        assert!(results.spike_results.is_some());
        assert!(results.stress_results.is_some());
    }
}