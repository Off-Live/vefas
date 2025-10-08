use vefas_types::VefasCanonicalBundle;

fn base_bundle() -> VefasCanonicalBundle {
    VefasCanonicalBundle::new(
        vec![0x16, 0x03, 0x03, 0x00, 0x10],
        vec![0x16, 0x03, 0x04, 0x00, 0x10],
        vec![0x16, 0x03, 0x04, 0x00, 0x20],
        vec![0x16, 0x03, 0x04, 0x00, 0x08],
        vec![0x16, 0x03, 0x04, 0x00, 0x10],
        [1u8; 32],
        vec![vec![1, 2, 3], vec![4, 5, 6]],
        {
            let mut v = vec![0x17, 0x03, 0x03, 0x00, 0x01];
            v.push(0xaa);
            v
        },
        {
            let mut v = vec![0x17, 0x03, 0x03, 0x00, 0x01];
            v.push(0xbb);
            v
        },
        "example.com".to_string(),
        1,
        200,
        [2u8; 32],
    )
    .unwrap()
}

#[test]
fn canonical_hash_same_for_identical_bundles() {
    let b1 = base_bundle();
    let b2 = base_bundle();
    assert_eq!(b1.bundle_hash(), b2.bundle_hash());
}

#[test]
fn canonical_hash_changes_on_domain_change() {
    let b1 = base_bundle();
    let mut b2 = base_bundle();
    b2.domain = "different.com".to_string();
    assert_ne!(b1.bundle_hash(), b2.bundle_hash());
}

#[test]
fn canonical_hash_changes_on_status_change() {
    let b1 = base_bundle();
    let mut b2 = base_bundle();
    b2.expected_status = 404;
    assert_ne!(b1.bundle_hash(), b2.bundle_hash());
}

#[test]
fn canonical_hash_changes_on_certificate_chain_order() {
    let b1 = base_bundle();

    // Create a bundle with reversed certificate chain order
    let b2 = VefasCanonicalBundle::new(
        vec![0x16, 0x03, 0x03, 0x00, 0x10],
        vec![0x16, 0x03, 0x04, 0x00, 0x10],
        vec![0x16, 0x03, 0x04, 0x00, 0x20],
        vec![0x16, 0x03, 0x04, 0x00, 0x08],
        vec![0x16, 0x03, 0x04, 0x00, 0x10],
        [1u8; 32],
        vec![vec![4, 5, 6], vec![1, 2, 3]], // Reversed order
        {
            let mut v = vec![0x17, 0x03, 0x03, 0x00, 0x01];
            v.push(0xaa);
            v
        },
        {
            let mut v = vec![0x17, 0x03, 0x03, 0x00, 0x01];
            v.push(0xbb);
            v
        },
        "example.com".to_string(),
        1,
        200,
        [2u8; 32],
    )
    .unwrap();

    // Different order should change hash
    assert_ne!(b1.bundle_hash(), b2.bundle_hash());
}
