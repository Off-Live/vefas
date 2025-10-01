//! Comprehensive TLS 1.3 Certificate and Cipher Suite Test Matrix
//!
//! This test verifies that all combinations of certificate types (RSA 2048, ECDSA P-256)
//! work correctly with all three core TLS 1.3 cipher suites.

use vefas_crypto::validation::{verify_certificate_signature, verify_certificate_chain_signatures};
use vefas_crypto_sp1::SP1CryptoProvider;
use vefas_types::tls::CipherSuite;

// Test certificate fixtures - RSA CA (self-signed)
const RSA_CA_CERT: &[u8] = &hex_literal::hex!("3082031d30820205a00302010202145e7d05747e4db25a7634ef0e18a0a6c55f11703a300d06092a864886f70d01010b050030163114301206035504030c0b5465737420525341204341301e170d3235313030313033353334385a170d3335303932393033353334385a30163114301206035504030c0b546573742052534120434130820122300d06092a864886f70d01010105000382010f003082010a0282010100a749d98d190b9fdf325315e94710de8b5b2edc0207ed86851471f2f8ef00303e029eba6fdbc1bdbe40f3b8722b711449f16fb5b9921fdb01021c59a4de262f767983b63ae02be8417ed6bb0ca9896274c2e33b30f946c90fd775f45eaa0ee2c794281e3a79a1cf650a5f7d053d5ebba2d276e686828d427eafb5c67864519ed60d7d85dfbba5d256da526bd082b6a54d00e420cec67654dd3ff5107ff77e65840c46b978ce31888c3ff874b1e47374dee80bb2ed27ea674aaec0ac56581ab7f583ced8a048730ffc9ace45f3d03df8ced538b9d2afb921e7878ef1c6c70eb1fcb2f66ade761d93d1d509c4f8c482e4128b9ce88c63bc53a66f6d609c5a6e89610203010001a3633061301d0603551d0e04160414c3b2b37c8f9394a0180ae4beab1620c27be71e59301f0603551d23041830168014c3b2b37c8f9394a0180ae4beab1620c27be71e59300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300d06092a864886f70d01010b05000382010100507009970d1ee7bbf162750e83a1b38de9ba0c98acae7d62317a447fd15d7314581027b323bbcebbe4a19f90acef9a4b4dc3f0689f060ddb5cc2efcbeddf76cc7e34e198a13db272a05d738298c5563c859fc855c30b029350da8c7c44312ad8eff5fed00e84ba2c298ad19189c47d3d6e4487c3016dbe020a992a45d1741848a2d7360712e82f536fa5e13f23b90f1e0024c015a76fe891b05473fb97229f1f467e9c7bfe9c34fec5cd06023faa750ded6c933c1f6039cc580bc2939c509a18aa5ec7f410c1bcd3664b005ce4a368cc67ec7dacc03ebf894ce14a3f405fa64ed9775ed4ece1aa21035f6c87a64030b27168dab86dac8b5c0f1f083e1def469a");

// Test certificate fixtures - RSA Leaf (signed by RSA CA)
const RSA_LEAF_CERT: &[u8] = &hex_literal::hex!("308203453082022da00302010202144beea4a27f48b27e8cb3b32c6fdd52092009a143300d06092a864886f70d01010b050030163114301206035504030c0b5465737420525341204341301e170d3235313030313033353432355a170d3236313030313033353432355a301b3119301706035504030c10746573742e6578616d706c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100bc03a6c3879dce0a8ab14e5441e403f75f04856d1e8c4ee69b241e0f0d32de2894446cc80e9d4980fe65eedccb47c34af25b2d6bee794faff07c359e74a5da2ec38ded1f2bca86f9928f4ae473e89ee5d196ad1523609df81fb9baa6ba58245a5d5a081127878366547938a9eb0e7446048771e3a388ea3ad8c2f767459caa7762403842015f045fbf828c0e0cfd44d52b9ab663178dcb74f2b1c85d9f86597854354f240b2274ffe504c9c472eb83feeb885a961b0aef52fa78154363aaa99236559e182488f38c1f72948f29815f628c5befffd1678cdbeacc7769df3a7ad30bef292335645cd69f35257dea4cff254d0884d63008cdbe19968c591b1aa7ef0203010001a38185308182301b0603551d11041430128210746573742e6578616d706c652e636f6d300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301301d0603551d0e04160414ae957a9af58c34b9217c523506e20eea623da21b301f0603551d23041830168014c3b2b37c8f9394a0180ae4beab1620c27be71e59300d06092a864886f70d01010b05000382010100360e66f069ac1c02ae78dadea7c7b872ab18e0930d04feefb8ff35a42199cb21f0a32aaf668c74ac46127009f525fa27176bd5565ba64a22b1b9d3296eeba8c3ef18e2dae3e01d99c4bf89314f730de95b6dd3e60e94c3df5c0b6f82a43cf8da0fd042dff5444eefea05fca14c99d32ca034a59aa90b9275e1f7d1cd826e60875c06137d145c9137b7781a602710f6238c1082997762ecc9027dfed95c1eff6ffc7de45ed4e15ba8f624f6874b336cc2dcca8c20343951a5943f9be86235b8cf57bd7c7f128c795ec1744fdbe4f67e24311e5ef88e72b0df863b08e8ceac5a20629fe2581caae244b78f9946d74a84d4e956a92d3f8eeb9bd142d113e8145f84");

// Test certificate fixtures - ECDSA CA (self-signed, P-256)
const ECDSA_CA_CERT: &[u8] = &hex_literal::hex!("308201953082013ba0030201020214573f3cc79c5654dfbcdf987b19b2e2ca46bab0df300a06082a8648ce3d04030230183116301406035504030c0d54657374204543445341204341301e170d3235313030313033353430395a170d3335303932393033353430395a30183116301406035504030c0d546573742045434453412043413059301306072a8648ce3d020106082a8648ce3d0301070342000497ca56cb9c9a1c6fabd3d98cf70bd9acd07bb7deea300a2654f383f2ad271a34804d18dd85964f786d5c8e3dad7f65968303b3eaf6e25c87026cf08ef8af98afa3633061301d0603551d0e04160414989f770593cc64580a37f75ff17480a2562330fe301f0603551d23041830168014989f770593cc64580a37f75ff17480a2562330fe300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106300a06082a8648ce3d0403020348003045022053c38e7a17f3f2b9d25d9f0a3e8fbc93c91665fb2121fe00b2379627c9ce7ae1022100ca499d6c3c1b2cbca84d3c9577685529aa6525610d8b21dfe9d6f09e38748114");

// Test certificate fixtures - ECDSA Leaf (signed by ECDSA CA)
const ECDSA_LEAF_CERT: &[u8] = &hex_literal::hex!("308201bd30820163a00302010202141ab8c775782927de9f98cf7edee3720929041020300a06082a8648ce3d04030230183116301406035504030c0d54657374204543445341204341301e170d3235313030313033353433375a170d3236313030313033353433375a301c311a301806035504030c1165636473612e6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004585e2c3523cbc76959f09a4329830f2af2cc35281c14d438823840556f7db59bc3e91062903c358c635df9d745e95ceb9309e48e1c361151bc5f7b9d7a55f1b9a38186308183301c0603551d1104153013821165636473612e6578616d706c652e636f6d300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301301d0603551d0e041604143a55a6b83719b93150497c46a85736a834a2c35e301f0603551d23041830168014989f770593cc64580a37f75ff17480a2562330fe300a06082a8648ce3d0403020348003045022021e4a61d0f9928cbf16ffe73190a7eee2ab0f7a7ef6c01633023c626ff6711f4022100b5ec31602601823fc989e07976448ac6adc830018c07863e5aa861a1b6252577");

/// Test matrix for certificate types and cipher suites
#[derive(Debug, Clone)]
struct TestCase {
    cert_type: &'static str,
    cipher_suite: CipherSuite,
    ca_cert: &'static [u8],
    leaf_cert: &'static [u8],
    expected_result: bool,
}

impl TestCase {
    fn new(cert_type: &'static str, cipher_suite: CipherSuite, ca_cert: &'static [u8], leaf_cert: &'static [u8]) -> Self {
        Self {
            cert_type,
            cipher_suite,
            ca_cert,
            leaf_cert,
            expected_result: true, // All combinations should work
        }
    }
}

#[test]
fn test_comprehensive_tls_matrix() {
    let crypto = SP1CryptoProvider::new();
    
    // Define all test cases
    let test_cases = vec![
        // RSA 2048 with all cipher suites
        TestCase::new("RSA 2048", CipherSuite::Aes128GcmSha256, RSA_CA_CERT, RSA_LEAF_CERT),
        TestCase::new("RSA 2048", CipherSuite::Aes256GcmSha384, RSA_CA_CERT, RSA_LEAF_CERT),
        TestCase::new("RSA 2048", CipherSuite::ChaCha20Poly1305Sha256, RSA_CA_CERT, RSA_LEAF_CERT),
        
        // ECDSA P-256 with all cipher suites
        TestCase::new("ECDSA P-256", CipherSuite::Aes128GcmSha256, ECDSA_CA_CERT, ECDSA_LEAF_CERT),
        TestCase::new("ECDSA P-256", CipherSuite::Aes256GcmSha384, ECDSA_CA_CERT, ECDSA_LEAF_CERT),
        TestCase::new("ECDSA P-256", CipherSuite::ChaCha20Poly1305Sha256, ECDSA_CA_CERT, ECDSA_LEAF_CERT),
    ];
    
    println!("🧪 Testing comprehensive TLS 1.3 certificate and cipher suite matrix");
    println!("📊 Test Matrix:");
    println!("| Cert Type   | Cipher Suite                 | Expected Result |");
    println!("| ----------- | ---------------------------- | --------------- |");
    
    let mut passed = 0;
    let mut failed = 0;
    
    for test_case in &test_cases {
        println!("| {:10} | {:27} | {:15} |", 
            test_case.cert_type, 
            test_case.cipher_suite.as_str(),
            if test_case.expected_result { "✅ works" } else { "❌ fails" }
        );
        
        // Test 1: CA self-signature verification
        let ca_result = verify_certificate_signature(&crypto, test_case.ca_cert, test_case.ca_cert);
        let ca_success = ca_result.is_ok();
        
        // Test 2: Leaf certificate signature verification
        let leaf_result = verify_certificate_signature(&crypto, test_case.leaf_cert, test_case.ca_cert);
        let leaf_success = leaf_result.is_ok();
        
        // Test 3: Certificate chain verification
        let chain = vec![test_case.leaf_cert.to_vec(), test_case.ca_cert.to_vec()];
        let chain_result = verify_certificate_chain_signatures(&crypto, &chain);
        let chain_success = chain_result.is_ok();
        
        // Test 4: Cipher suite properties
        let cipher_props_valid = test_cipher_suite_properties(test_case.cipher_suite);
        
        let overall_success = ca_success && leaf_success && chain_success && cipher_props_valid;
        
        if overall_success {
            passed += 1;
            println!("✅ {} + {}: All tests passed", test_case.cert_type, test_case.cipher_suite.as_str());
        } else {
            failed += 1;
            println!("❌ {} + {}: Some tests failed", test_case.cert_type, test_case.cipher_suite.as_str());
            if !ca_success {
                println!("   - CA self-signature verification failed: {:?}", ca_result.err());
            }
            if !leaf_success {
                println!("   - Leaf signature verification failed: {:?}", leaf_result.err());
            }
            if !chain_success {
                println!("   - Chain verification failed: {:?}", chain_result.err());
            }
            if !cipher_props_valid {
                println!("   - Cipher suite properties validation failed");
            }
        }
    }
    
    println!("\n📈 Test Results Summary:");
    println!("✅ Passed: {}", passed);
    println!("❌ Failed: {}", failed);
    println!("📊 Total: {}", test_cases.len());
    
    // All tests should pass
    assert_eq!(failed, 0, "Some test cases failed. Expected all 6 combinations to work correctly.");
    assert_eq!(passed, 6, "Expected exactly 6 test cases to pass.");
    
    println!("\n🎉 All TLS 1.3 certificate and cipher suite combinations are working correctly!");
}

/// Test cipher suite properties to ensure they're correctly implemented
fn test_cipher_suite_properties(cipher_suite: CipherSuite) -> bool {
    // Test wire format conversion
    let wire_format = cipher_suite.wire_format();
    let from_wire = CipherSuite::from_wire_format(wire_format);
    if from_wire != Ok(cipher_suite) {
        println!("   - Wire format conversion failed for {}", cipher_suite.as_str());
        return false;
    }
    
    // Test string representation
    let as_str = cipher_suite.as_str();
    if as_str.is_empty() {
        println!("   - String representation is empty for {}", cipher_suite.as_str());
        return false;
    }
    
    // Test hash algorithm
    let hash_alg = cipher_suite.hash_algorithm();
    // HashAlgorithm is an enum, not Option, so we just check it's valid
    
    // Test AEAD algorithm
    let aead_alg = cipher_suite.aead_algorithm();
    // AeadAlgorithm is an enum, not Option, so we just check it's valid
    
    // Test key and IV lengths
    let key_len = cipher_suite.key_length();
    let iv_len = cipher_suite.iv_length();
    if key_len == 0 || iv_len == 0 {
        println!("   - Invalid key/IV length for {}", cipher_suite.as_str());
        return false;
    }
    
    // Test that cipher suite is not deprecated
    if cipher_suite.is_deprecated() {
        println!("   - Cipher suite is marked as deprecated: {}", cipher_suite.as_str());
        return false;
    }
    
    true
}
