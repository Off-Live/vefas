//! Native hash implementation tests with NIST test vectors
//!
//! This module contains comprehensive tests for SHA-256 and SHA-384 implementations
//! using official NIST test vectors to ensure cryptographic correctness.

use hex_literal::hex;
use zktls_crypto::native::NativeCryptoProvider;
use zktls_crypto::traits::{Hash, PrecompileDetection};

#[test]
fn test_sha256_empty_input() {
    let provider = NativeCryptoProvider::new();
    let result = provider.sha256(&[]);
    
    // NIST test vector: SHA-256 of empty string
    let expected = hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(result, expected);
}

#[test]
fn test_sha256_abc() {
    let provider = NativeCryptoProvider::new();
    let result = provider.sha256(b"abc");
    
    // NIST test vector: SHA-256 of "abc"
    let expected = hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(result, expected);
}

#[test]
fn test_sha256_longer_message() {
    let provider = NativeCryptoProvider::new();
    let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let result = provider.sha256(input);
    
    // NIST test vector: SHA-256 of "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    let expected = hex!("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    assert_eq!(result, expected);
}

#[test]
fn test_sha256_one_million_a() {
    let provider = NativeCryptoProvider::new();
    let input = vec![b'a'; 1_000_000];
    let result = provider.sha256(&input);
    
    // NIST test vector: SHA-256 of one million 'a's
    let expected = hex!("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    assert_eq!(result, expected);
}

#[test]
fn test_sha384_empty_input() {
    let provider = NativeCryptoProvider::new();
    let result = provider.sha384(&[]);
    
    // NIST test vector: SHA-384 of empty string
    let expected = hex!(
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );
    assert_eq!(result, expected);
}

#[test]
fn test_sha384_abc() {
    let provider = NativeCryptoProvider::new();
    let result = provider.sha384(b"abc");
    
    // NIST test vector: SHA-384 of "abc"
    let expected = hex!(
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    );
    assert_eq!(result, expected);
}

#[test]
fn test_sha384_longer_message() {
    let provider = NativeCryptoProvider::new();
    let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    let result = provider.sha384(input);
    
    // NIST test vector: SHA-384 of long message
    let expected = hex!(
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
    );
    assert_eq!(result, expected);
}

#[test]
fn test_sha384_one_million_a() {
    let provider = NativeCryptoProvider::new();
    let input = vec![b'a'; 1_000_000];
    let result = provider.sha384(&input);
    
    // NIST test vector: SHA-384 of one million 'a's
    let expected = hex!(
        "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
    );
    assert_eq!(result, expected);
}

#[test]
fn test_hash_precompile_detection() {
    let provider = NativeCryptoProvider::new();
    
    // Native implementation should never report precompile support
    assert!(!provider.has_precompile_support());
    assert!(!provider.has_any_precompiles());
    assert_eq!(provider.platform_name(), None);
}

#[test]
fn test_hash_deterministic() {
    let provider = NativeCryptoProvider::new();
    let input = b"deterministic test input";
    
    // Multiple calls should produce identical results
    let result1 = provider.sha256(input);
    let result2 = provider.sha256(input);
    let result3 = provider.sha256(input);
    
    assert_eq!(result1, result2);
    assert_eq!(result2, result3);
    
    // Same for SHA-384
    let result1 = provider.sha384(input);
    let result2 = provider.sha384(input);
    
    assert_eq!(result1, result2);
}

#[cfg(feature = "std")]
#[test]
fn test_hash_thread_safety() {
    use std::thread;
    use std::sync::Arc;
    
    let provider = Arc::new(NativeCryptoProvider::new());
    let input = b"thread safety test";
    
    let handles: Vec<_> = (0..10).map(|_| {
        let provider = Arc::clone(&provider);
        thread::spawn(move || {
            provider.sha256(input)
        })
    }).collect();
    
    let results: Vec<[u8; 32]> = handles.into_iter()
        .map(|h| h.join().unwrap())
        .collect();
    
    // All results should be identical
    let first_result = results[0];
    for result in &results[1..] {
        assert_eq!(*result, first_result);
    }
}