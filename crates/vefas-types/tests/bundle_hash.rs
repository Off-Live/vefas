use vefas_types::VefasCanonicalBundle;

fn base_bundle() -> VefasCanonicalBundle {
    VefasCanonicalBundle::new(
        vec![1, 2, 3],
        vec![4, 5, 6],
        vec![7, 8],
        vec![9],
        vec![10],
        [11u8; 32],
        vec![vec![1]],
        vec![0x17, 0x03, 0x03, 0, 1, 0xaa],
        vec![0x17, 0x03, 0x03, 0, 1, 0xbb],
        "example.com".to_string(),
        1,
        200,
        [2u8; 32],
    )
    .unwrap()
}

#[test]
fn bundle_hash_deterministic_and_sensitive() {
    let b1 = base_bundle();
    let b2 = base_bundle();
    assert_eq!(b1.bundle_hash(), b2.bundle_hash());

    let mut b3 = base_bundle();
    b3.domain = "different.com".to_string();
    assert_ne!(b1.bundle_hash(), b3.bundle_hash());
}
