//! Bundle compression using LZSS algorithm
//!
//! This module implements production-grade compression for VEFAS canonical bundles
//! using the LZSS algorithm optimized for TLS data patterns. The compression is
//! designed to be deterministic and compatible with no_std environments.
//!
//! ## Compression Strategy
//!
//! TLS data contains significant redundancy that LZSS can exploit:
//! - Certificate chains: Repeated OIDs, DN components, and structured data
//! - Handshake messages: Standard protocol patterns and extensions
//! - Application records: HTTP headers and content patterns
//!
//! ## Performance Impact
//!
//! - **Compression ratio**: 30-50% size reduction typical for TLS bundles
//! - **Memory overhead**: Minimal in no_std environments
//! - **Proof generation**: Significantly faster due to smaller input size
//!
//! ## Security Considerations
//!
//! - Compression is applied to the entire bundle after cryptographic verification
//! - No compression-based side channels as data is already captured
//! - Deterministic compression ensures consistent proof generation

extern crate alloc;
use alloc::{format, vec, vec::Vec};
use core::mem::size_of;

use lzss::{Lzss, SliceReader, SliceWriter};
use serde::{Deserialize, Serialize};

use crate::{VefasError, VefasResult};

/// LZSS compression configuration optimized for TLS data
///
/// Parameters chosen based on TLS data characteristics:
/// - EI: 12 bits (4KB window) - good for certificate chain patterns
/// - EJ: 4 bits (16 byte match length) - typical for TLS structure repetition
/// - C: 0x20 (space character) - common in certificate text fields
/// - N: 4KB - matches typical TLS record sizes
/// - N2: 8KB - double buffer for efficient processing
type TlsLzss = Lzss<12, 4, 0x20, { 1 << 12 }, { 2 << 12 }>;

/// Compressed bundle format with metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressedBundle {
    /// Compression format version for future compatibility
    pub version: u16,
    /// Original bundle size before compression
    pub original_size: u32,
    /// Compressed data
    pub compressed_data: Vec<u8>,
    /// Compression algorithm identifier
    pub algorithm: CompressionAlgorithm,
    /// Compression parameters for verification
    pub parameters: CompressionParameters,
}

/// Supported compression algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    /// LZSS compression optimized for TLS data
    LzssTls,
}

/// Compression algorithm parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionParameters {
    /// Window size in bits (EI parameter)
    pub window_bits: u8,
    /// Match length bits (EJ parameter)
    pub match_bits: u8,
    /// Character parameter (C parameter)
    pub character: u8,
}

impl Default for CompressionParameters {
    fn default() -> Self {
        Self {
            window_bits: 12, // 4KB window
            match_bits: 4,   // 16 byte max match
            character: 0x20, // space character
        }
    }
}

impl CompressedBundle {
    /// Create a new compressed bundle with metadata
    pub fn new(
        original_size: u32,
        compressed_data: Vec<u8>,
        algorithm: CompressionAlgorithm,
        parameters: CompressionParameters,
    ) -> Self {
        Self {
            version: 1, // Current compression format version
            original_size,
            compressed_data,
            algorithm,
            parameters,
        }
    }

    /// Get compression ratio as a percentage
    pub fn compression_ratio(&self) -> f32 {
        if self.original_size == 0 {
            return 0.0;
        }
        (self.compressed_data.len() as f32 / self.original_size as f32) * 100.0
    }

    /// Get space saved in bytes
    pub fn space_saved(&self) -> u32 {
        self.original_size
            .saturating_sub(self.compressed_data.len() as u32)
    }

    /// Validate compressed bundle structure
    pub fn validate(&self) -> VefasResult<()> {
        // Check version compatibility
        if self.version != 1 {
            return Err(VefasError::invalid_input(
                "compression_version",
                &format!("Unsupported compression version: {}", self.version),
            ));
        }

        // Validate original size
        if self.original_size == 0 {
            return Err(VefasError::invalid_input(
                "original_size",
                "Original size cannot be zero",
            ));
        }

        // Check compressed data is not empty
        if self.compressed_data.is_empty() {
            return Err(VefasError::invalid_input(
                "compressed_data",
                "Compressed data cannot be empty",
            ));
        }

        // Validate compression ratio is reasonable (should be < 100%)
        if self.compressed_data.len() as u32 >= self.original_size {
            return Err(VefasError::invalid_input(
                "compression_ratio",
                "Invalid compression ratio - compressed size >= original size",
            ));
        }

        // Validate algorithm-specific parameters
        match self.algorithm {
            CompressionAlgorithm::LzssTls => {
                if self.parameters.window_bits < 8 || self.parameters.window_bits > 16 {
                    return Err(VefasError::invalid_input(
                        "window_bits",
                        "Window bits must be between 8 and 16",
                    ));
                }
                if self.parameters.match_bits < 2 || self.parameters.match_bits > 8 {
                    return Err(VefasError::invalid_input(
                        "match_bits",
                        "Match bits must be between 2 and 8",
                    ));
                }
            }
        }

        Ok(())
    }

    /// Get memory footprint of compressed bundle
    pub fn memory_footprint(&self) -> usize {
        size_of::<Self>() + self.compressed_data.len()
    }
}

/// Bundle compression utilities
#[derive(Debug)]
pub struct BundleCompressor;

impl BundleCompressor {
    /// Compress data using LZSS algorithm optimized for TLS patterns
    pub fn compress(data: &[u8]) -> VefasResult<CompressedBundle> {
        if data.is_empty() {
            return Err(VefasError::invalid_input(
                "input_data",
                "Cannot compress empty data",
            ));
        }

        // Allocate output buffer - LZSS can expand data in worst case
        // Use 110% of original size plus 1KB overhead as safe upper bound
        let max_output_size = (data.len() * 11 / 10) + 1024;
        let mut output = vec![0u8; max_output_size];

        // Perform LZSS compression
        let reader = SliceReader::new(data);
        let writer = SliceWriter::new(&mut output);

        let compressed_size = TlsLzss::compress_stack(reader, writer).map_err(|_| {
            VefasError::crypto_error(
                crate::errors::CryptoErrorType::CipherFailed,
                "LZSS compression failed",
            )
        })?;

        // Truncate output to actual compressed size
        output.truncate(compressed_size);

        // Validate compression was beneficial
        if output.len() >= data.len() {
            return Err(VefasError::crypto_error(
                crate::errors::CryptoErrorType::CipherFailed,
                "Compression did not reduce data size - data may not be compressible",
            ));
        }

        Ok(CompressedBundle::new(
            data.len() as u32,
            output,
            CompressionAlgorithm::LzssTls,
            CompressionParameters::default(),
        ))
    }

    /// Decompress data and verify integrity
    pub fn decompress(compressed: &CompressedBundle) -> VefasResult<Vec<u8>> {
        // Validate compressed bundle
        compressed.validate()?;

        // Verify algorithm is supported
        match compressed.algorithm {
            CompressionAlgorithm::LzssTls => {
                // Allocate output buffer for decompressed data
                let mut output = vec![0u8; compressed.original_size as usize];

                // Perform LZSS decompression
                let reader = SliceReader::new(&compressed.compressed_data);
                let writer = SliceWriter::new(&mut output);

                let decompressed_size =
                    TlsLzss::decompress_stack(reader, writer).map_err(|_| {
                        VefasError::crypto_error(
                            crate::errors::CryptoErrorType::CipherFailed,
                            "LZSS decompression failed",
                        )
                    })?;

                // Verify decompressed size matches expected
                if decompressed_size != compressed.original_size as usize {
                    return Err(VefasError::crypto_error(
                        crate::errors::CryptoErrorType::CipherFailed,
                        &format!(
                            "Decompressed size mismatch: expected {}, got {}",
                            compressed.original_size, decompressed_size
                        ),
                    ));
                }

                // Truncate to exact size (should be no-op if above check passed)
                output.truncate(decompressed_size);
                Ok(output)
            }
        }
    }

    /// Estimate compression ratio for given data without actually compressing
    /// This is useful for deciding whether compression is worthwhile
    pub fn estimate_compression_ratio(data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }

        // Simple heuristic based on byte frequencies and repetition patterns
        // This gives a rough estimate without expensive compression
        let mut byte_counts = [0u32; 256];
        let mut repetition_score = 0u32;

        // Count byte frequencies and detect simple repetitions
        for (i, &byte) in data.iter().enumerate() {
            byte_counts[byte as usize] += 1;

            // Check for adjacent byte repetitions (simple pattern detection)
            if i > 0 && data[i - 1] == byte {
                repetition_score += 1;
            }
        }

        // Calculate compressibility based on byte distribution
        let data_len = data.len() as f32;
        let mut unique_bytes = 0u32;
        let mut max_frequency = 0u32;

        for &count in &byte_counts {
            if count > 0 {
                unique_bytes += 1;
                if count > max_frequency {
                    max_frequency = count;
                }
            }
        }

        // Heuristic compression estimation without logarithms
        // Higher unique byte count = worse compression
        let diversity_factor = (unique_bytes as f32 / 256.0).min(1.0);

        // Higher max frequency = better compression
        let concentration_factor = (max_frequency as f32 / data_len).min(0.8);

        // Adjacent repetitions indicate good compression potential
        let repetition_factor = (repetition_score as f32 / data_len).min(0.5);

        // Combine factors to estimate compression ratio
        // Start with baseline 75% and adjust based on factors
        let base_ratio = 75.0;
        let diversity_penalty = diversity_factor * 20.0; // More diverse = worse compression
        let concentration_bonus = concentration_factor * 25.0; // More concentrated = better
        let repetition_bonus = repetition_factor * 30.0; // More repetition = better

        let estimated_ratio =
            base_ratio + diversity_penalty - concentration_bonus - repetition_bonus;
        estimated_ratio.max(20.0).min(95.0) // Clamp to reasonable bounds
    }

    /// Check if data is likely to benefit from compression
    pub fn should_compress(data: &[u8]) -> bool {
        if data.len() < 1024 {
            return false; // Too small to benefit from compression overhead
        }

        let estimated_ratio = Self::estimate_compression_ratio(data);
        estimated_ratio < 85.0 // Compress if we expect >15% reduction
    }

    /// Get compression statistics for analysis
    pub fn compression_stats(original: &[u8], compressed: &CompressedBundle) -> CompressionStats {
        let ratio_x100 = (compressed.compression_ratio() * 100.0) as u32;
        CompressionStats {
            original_size: original.len(),
            compressed_size: compressed.compressed_data.len(),
            compression_ratio_x100: ratio_x100,
            space_saved: compressed.space_saved(),
            algorithm: compressed.algorithm,
        }
    }
}

/// Compression statistics for analysis and monitoring
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionStats {
    /// Original data size in bytes
    pub original_size: usize,
    /// Compressed data size in bytes
    pub compressed_size: usize,
    /// Compression ratio as percentage * 100 (e.g., 7500 = 75.00%)
    pub compression_ratio_x100: u32,
    /// Bytes saved through compression
    pub space_saved: u32,
    /// Algorithm used for compression
    pub algorithm: CompressionAlgorithm,
}

impl CompressionStats {
    /// Get compression ratio as a float
    pub fn compression_ratio(&self) -> f32 {
        self.compression_ratio_x100 as f32 / 100.0
    }

    /// Check if compression was effective (>20% reduction)
    pub fn is_effective(&self) -> bool {
        self.compression_ratio_x100 < 8000 // Less than 80%
    }

    /// Get human-readable compression summary
    pub fn summary(&self) -> alloc::string::String {
        format!(
            "Compressed {} bytes to {} bytes ({:.1}% ratio, {} bytes saved)",
            self.original_size,
            self.compressed_size,
            self.compression_ratio(),
            self.space_saved
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_decompression_roundtrip() {
        // Test data that should compress well (repetitive pattern)
        let original_data = b"Hello World! ".repeat(100);

        // Compress the data
        let compressed = BundleCompressor::compress(&original_data).unwrap();

        // Verify compression was beneficial
        assert!(compressed.compressed_data.len() < original_data.len());
        assert!(compressed.compression_ratio() < 80.0);

        // Decompress and verify
        let decompressed = BundleCompressor::decompress(&compressed).unwrap();
        assert_eq!(decompressed, original_data);
    }

    #[test]
    fn test_compression_validation() {
        // Use repetitive data that will compress well
        let original_data = b"Test data for compression validation! ".repeat(50);

        let mut compressed = BundleCompressor::compress(&original_data).unwrap();

        // Valid bundle should pass validation
        assert!(compressed.validate().is_ok());

        // Invalid version should fail
        compressed.version = 999;
        assert!(compressed.validate().is_err());
    }

    #[test]
    fn test_compression_estimation() {
        // Highly repetitive data should have low estimated ratio
        let repetitive_data = b"A".repeat(1000);
        let ratio = BundleCompressor::estimate_compression_ratio(&repetitive_data);
        assert!(ratio < 50.0);

        // Random-like data should have high estimated ratio
        let random_data: Vec<u8> = (0..1000).map(|i| (i * 17 + 42) as u8).collect();
        let ratio = BundleCompressor::estimate_compression_ratio(&random_data);
        assert!(ratio > 60.0);
    }

    #[test]
    fn test_should_compress_logic() {
        // Small data should not be compressed
        assert!(!BundleCompressor::should_compress(b"small"));

        // Large repetitive data should be compressed
        let large_repetitive = b"Pattern! ".repeat(200);
        assert!(BundleCompressor::should_compress(&large_repetitive));
    }

    #[test]
    fn test_compression_stats() {
        let original = b"Test data ".repeat(50);
        let compressed = BundleCompressor::compress(&original).unwrap();

        let stats = BundleCompressor::compression_stats(&original, &compressed);

        assert_eq!(stats.original_size, original.len());
        assert_eq!(stats.compressed_size, compressed.compressed_data.len());
        assert!(stats.is_effective());
        assert!(!stats.summary().is_empty());
    }

    #[test]
    fn test_empty_data_handling() {
        // Empty data should return error
        assert!(BundleCompressor::compress(&[]).is_err());
    }

    #[test]
    fn test_incompressible_data_handling() {
        // Create data that won't compress well (random bytes)
        let random_data: Vec<u8> = (0..100).map(|i| (i * 251 + 17) as u8).collect();

        // Should fail compression due to no size reduction
        let result = BundleCompressor::compress(&random_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_bundle_memory_footprint() {
        let data = b"Test data for memory footprint calculation".repeat(10);
        let compressed = BundleCompressor::compress(&data).unwrap();

        let footprint = compressed.memory_footprint();
        assert!(footprint >= compressed.compressed_data.len());
        assert!(footprint < data.len()); // Should be smaller than original
    }
}
