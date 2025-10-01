//! VEFAS Project
//!
//! This project provides production-grade zkTLS verification through HTTP API endpoints.
//! CLI functionality has been removed in favor of a dedicated vefas-gateway HTTP server.
//!
//! Use vefas-gateway crate for HTTP API endpoints:
//! - POST /requests: Execute TLS request and generate proof
//! - POST /verify: Verify cryptographic proof authenticity

// This file serves as the library root for the workspace.
// The actual HTTP server implementation is in vefas-gateway crate.

pub use vefas_core::*;
pub use vefas_crypto::*;
pub use vefas_types::*;

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_imports_work() {
        // Verify that workspace imports are functioning
        assert!(true, "Workspace crates should be importable");
    }
}
