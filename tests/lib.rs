//! VEFAS comprehensive testing library
//!
//! This library provides comprehensive testing capabilities for the VEFAS project,
//! including security testing, end-to-end validation, and performance benchmarking.

pub mod security_tests;
pub mod e2e_tests;

// Re-export main security testing functionality
pub use security_tests::{
    VefasSecurityTestSuite,
    SecurityTestResults,
    FuzzingResults,
    AttackVectorResults,
    PerformanceSecurityResults,
};

// Re-export main E2E testing functionality
pub use e2e_tests::{
    E2ETestSuite,
    E2ETestConfig,
    E2ETestResults,
};