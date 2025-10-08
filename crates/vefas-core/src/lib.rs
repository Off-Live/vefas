//! # VEFAS Core HTTP Client
//!
//! Production-grade HTTP client with rustls integration for zkTLS verification.
//! Supports both std (host) and no_std (guest) environments with pluggable crypto providers.
//!
//! ## Design Principles
//!
//! - **Production ready**: Battle-tested rustls foundation with comprehensive error handling
//! - **Dual environment**: Works in both std (host) and no_std (guest) modes
//! - **Pluggable crypto**: Uses any rustls CryptoProvider implementation
//! - **Complete TLS capture**: Extracts handshake transcript, certificates, and session keys
//! - **Zero shortcuts**: No mocks, simplified approaches, or shortcuts
//!
//! ## Architecture
//!
//! ```text
//! VefasClient<P>
//! ├── Crypto Provider (SP1/RISC0/aws-lc-rs)
//! ├── TLS Session Capture
//! │   ├── Handshake Transcript
//! │   ├── Certificate Chain
//! │   └── Session Keys
//! ├── HTTP Processing
//! │   ├── Request Parsing
//! │   ├── Response Processing
//! │   └── Data Commitment
//! └── Verification (no_std mode)
//!     ├── TLS Verification
//!     ├── Certificate Validation
//!     └── Proof Generation
//! ```
//!
//! ## Usage
//!
//! ### Host Mode (std)
//! ```rust
//! use vefas_core::VefasClient;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = VefasClient::new()?;
//! let bundle = client.execute_request("GET", "https://api.example.com/data").await?;
//! # Ok(())
//! # }
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(
    missing_docs,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]
#![warn(missing_debug_implementations)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod error;

#[cfg(feature = "std")]
mod client;

#[cfg(feature = "std")]
mod transport;

#[cfg(feature = "std")]
mod keylog;

#[cfg(feature = "std")]
mod session;

#[cfg(feature = "std")]
mod http;

#[cfg(feature = "std")]
mod records;

#[cfg(feature = "std")]
mod bundle;

#[cfg(feature = "std")]
mod bundle_validation;

mod cryptographic_validator;
mod guest_validator;

pub use error::{Result, VefasCoreError};

#[cfg(feature = "std")]
pub use client::{TlsConnection, VefasClient};

#[cfg(feature = "std")]
pub use transport::TlsTee;

#[cfg(feature = "std")]
pub use keylog::{SecretEntry, VefasKeyLog};

#[cfg(feature = "std")]
pub use session::SessionData;

#[cfg(feature = "std")]
pub use http::{HttpData, HttpHeaders, HttpProcessor, HttpRequest, HttpResponse};

#[cfg(feature = "std")]
pub use records::{
    ContentType, HandshakeMessage, HandshakeType, TlsExtension, TlsExtensionType, TlsRecord,
    TlsRecordParser,
};

#[cfg(feature = "std")]
pub use bundle::BundleBuilder;

#[cfg(feature = "std")]
pub use bundle_validation::{
    BundleValidator, ValidationError, ValidationMetadata, ValidationReport, ValidationWarning,
};

pub use cryptographic_validator::{
    CryptographicValidator, CryptographicValidationError, CryptographicValidationReport,
    CryptographicValidationMetadata,
};

pub use guest_validator::{
    GuestValidator, GuestValidationError, GuestValidationReport, GuestValidationMetadata,
};
