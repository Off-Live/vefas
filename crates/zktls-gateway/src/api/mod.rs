//! HTTP API server for zkTLS gateway
//!
//! This module provides REST API endpoints for the zkTLS gateway,
//! enabling programmatic access to proof generation and verification.

pub mod server;
pub mod handlers;
pub mod routes;

pub use server::ApiServer;
pub use handlers::*;
pub use routes::*;
