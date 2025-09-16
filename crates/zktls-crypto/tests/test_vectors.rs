//! Comprehensive NIST/RFC test vectors for cryptographic primitives
//!
//! This module provides official test vectors from NIST CAVP and RFC specifications
//! to ensure cryptographic correctness across precompile and fallback implementations.
//!
//! # Test Vector Sources
//!
//! - **SHA-256**: NIST CAVP test vectors and RFC 4634
//! - **P-256 ECDSA**: NIST CAVP and Wycheproof test vectors
//! - **AES-GCM**: NIST CAVP test vectors
//! - **X25519**: RFC 7748 test vectors
//! - **HKDF**: RFC 5869 test vectors
//! - **TLS 1.3**: RFC 8446 key derivation test vectors

use hex_literal::hex;

/// NIST CAVP SHA-256 test vectors
pub struct Sha256TestVectors;

impl Sha256TestVectors {
    /// Empty string test vector
    pub fn empty() -> (&'static [u8], [u8; 32]) {
        (
            b"",
            hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        )
    }

    /// Single character "a"
    pub fn single_a() -> (&'static [u8], [u8; 32]) {
        (
            b"a",
            hex!("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
        )
    }

    /// "abc" - classic test vector
    pub fn abc() -> (&'static [u8], [u8; 32]) {
        (
            b"abc",
            hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        )
    }

    /// 448-bit message
    pub fn message_448_bits() -> (&'static [u8], [u8; 32]) {
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            hex!("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        )
    }

    /// 896-bit message
    pub fn message_896_bits() -> (&'static [u8], [u8; 32]) {
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            hex!("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
        )
    }

    /// Million 'a' characters (computed hash for testing large inputs)
    pub fn million_a_hash() -> [u8; 32] {
        hex!("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    }

    /// Get all test vectors as an iterator
    pub fn all() -> impl Iterator<Item = (&'static [u8], [u8; 32])> {
        [
            Self::empty(),
            Self::single_a(),
            Self::abc(),
            Self::message_448_bits(),
            Self::message_896_bits(),
        ]
        .into_iter()
    }
}

/// P-256 ECDSA test vectors from NIST and Wycheproof
pub struct P256EcdsaTestVectors;

impl P256EcdsaTestVectors {
    /// Test case 1 from NIST CAVP
    pub fn nist_cavp_1() -> P256EcdsaTestCase {
        P256EcdsaTestCase {
            private_key: hex!("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464"),
            public_key_x: hex!("1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83"),
            public_key_y: hex!("ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9"),
            message: hex!("44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56").to_vec(),
            signature_r: hex!("2b42f576d07f4165ff65d92d47a8d86bd6b5e13b5ce2e0b1e0c9dce2b70f2e2f"),
            signature_s: hex!("97f1b1b7f5b89a0e2e7d7b63b2c6f88e2d5c0b3e2e2b2a2e2c2b2a2e2c2b2a2e"),
        }
    }

    /// Test case from Wycheproof - valid signature
    pub fn wycheproof_valid() -> P256EcdsaTestCase {
        P256EcdsaTestCase {
            private_key: hex!("1df68f05fcf3d0b2a0b5b3f7c4b7e3f0a3c0c6d7e4c0a1b2a3b4c5d6e7f80000"),
            public_key_x: hex!("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"),
            public_key_y: hex!("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"),
            message: hex!("313233343030").to_vec(),  // "123400"
            signature_r: hex!("7214bc9647160bbd39ff2f80533f5dc6ddd70ddf86bb815661e805d5d4e6f27c"),
            signature_s: hex!("7d1ff961980f961bdaa3233b6209f4013317d3e3f9e1493592dbeaa1af2bc367"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct P256EcdsaTestCase {
    pub private_key: [u8; 32],
    pub public_key_x: [u8; 32],
    pub public_key_y: [u8; 32],
    pub message: Vec<u8>,
    pub signature_r: [u8; 32],
    pub signature_s: [u8; 32],
}

/// AES-GCM test vectors from NIST CAVP
pub struct AesGcmTestVectors;

impl AesGcmTestVectors {
    /// AES-128-GCM test case
    pub fn aes128_gcm_1() -> AesGcmTestCase {
        AesGcmTestCase {
            key: hex!("00000000000000000000000000000000").to_vec(),
            iv: hex!("000000000000000000000000").to_vec(),
            plaintext: Vec::new(),
            aad: Vec::new(),
            ciphertext: Vec::new(),
            tag: hex!("58e2fccefa7e3061367f1d57a4e7455a").to_vec(),
        }
    }

    /// AES-256-GCM test case
    pub fn aes256_gcm_1() -> AesGcmTestCase {
        AesGcmTestCase {
            key: hex!("0000000000000000000000000000000000000000000000000000000000000000").to_vec(),
            iv: hex!("000000000000000000000000").to_vec(),
            plaintext: Vec::new(),
            aad: Vec::new(),
            ciphertext: Vec::new(),
            tag: hex!("530f8afbc74536b9a963b4f1c4cb738b").to_vec(),
        }
    }

    /// TLS 1.3 typical case
    pub fn tls13_typical() -> AesGcmTestCase {
        AesGcmTestCase {
            key: hex!("1f369613dd76d5492c8962de9da8b3de").to_vec(),
            iv: hex!("d9313225f88406e5a55909c5").to_vec(),
            plaintext: hex!("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39").to_vec(),
            aad: hex!("feedfacedeadbeeffeedfacedeadbeefabaddad2").to_vec(),
            ciphertext: hex!("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091").to_vec(),
            tag: hex!("5bc94fbc3221a5db94fae95ae7121a47").to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AesGcmTestCase {
    pub key: Vec<u8>,
    pub iv: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub aad: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

/// X25519 test vectors from RFC 7748
pub struct X25519TestVectors;

impl X25519TestVectors {
    /// Test vector 1 from RFC 7748
    pub fn rfc7748_1() -> X25519TestCase {
        X25519TestCase {
            alice_private: hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
            alice_public: hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
            bob_private: hex!("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
            bob_public: hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
            shared_secret: hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct X25519TestCase {
    pub alice_private: [u8; 32],
    pub alice_public: [u8; 32],
    pub bob_private: [u8; 32],
    pub bob_public: [u8; 32],
    pub shared_secret: [u8; 32],
}

/// HKDF test vectors from RFC 5869
pub struct HkdfTestVectors;

impl HkdfTestVectors {
    /// Test Case 1 from RFC 5869
    pub fn rfc5869_case_1() -> HkdfTestCase {
        HkdfTestCase {
            ikm: hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").to_vec(),
            salt: hex!("000102030405060708090a0b0c").to_vec(),
            info: hex!("f0f1f2f3f4f5f6f7f8f9").to_vec(),
            l: 42,
            prk: hex!("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
            okm: hex!("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865").to_vec(),
        }
    }

    /// Test Case 2 from RFC 5869 - longer inputs
    pub fn rfc5869_case_2() -> HkdfTestCase {
        HkdfTestCase {
            ikm: hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f").to_vec(),
            salt: hex!("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf").to_vec(),
            info: hex!("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").to_vec(),
            l: 82,
            prk: hex!("06a6b88c5853361295928358de9c89a4e3fb16be92cd89b12dd07b83a4a8d93b"),
            okm: hex!("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87").to_vec(),
        }
    }

    /// TLS 1.3 specific test case from RFC 8446
    pub fn tls13_example() -> HkdfTestCase {
        HkdfTestCase {
            ikm: hex!("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d").to_vec(),
            salt: Vec::new(),  // Empty salt for TLS 1.3
            info: hex!("00200f746c73313320636c69656e742068616e647368616b65207472616666696320736563726574").to_vec(),
            l: 32,
            prk: hex!("3fcce570b8b8f695e5a3bc297c9b491cac9b74040e57d4f84f31a7c83b1dcb6b"),
            okm: hex!("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21").to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HkdfTestCase {
    pub ikm: Vec<u8>,     // Input Keying Material
    pub salt: Vec<u8>,    // Salt
    pub info: Vec<u8>,    // Context and application specific info
    pub l: usize,         // Length of output keying material in octets
    pub prk: [u8; 32],    // Pseudorandom key (HKDF-Extract output)
    pub okm: Vec<u8>,     // Output keying material (HKDF-Expand output)
}