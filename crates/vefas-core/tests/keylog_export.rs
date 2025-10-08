use rustls::KeyLog;
use vefas_core::VefasKeyLog;

#[test]
fn export_is_deterministic_and_sorted() {
    let keylog = VefasKeyLog::new();
    let cr1 = [0x01u8; 32];
    let cr2 = [0x02u8; 32];

    // Mixed labels and client_randoms out of order
    keylog.log("SERVER_TRAFFIC_SECRET_0", &cr2, b"bb");
    keylog.log("CLIENT_HANDSHAKE_TRAFFIC_SECRET", &cr1, b"aa");
    keylog.log("CLIENT_TRAFFIC_SECRET_0", &cr2, b"cc");
    keylog.log("SERVER_HANDSHAKE_TRAFFIC_SECRET", &cr1, b"dd");

    let export1 = keylog.export_sslkeylogfile_format().expect("export");
    let export2 = keylog.export_sslkeylogfile_format().expect("export");

    // Deterministic across calls
    assert_eq!(export1, export2);

    // Sorted by label then client_random hex
    let lines: Vec<&str> = export1.trim().split('\n').collect();
    let mut sorted = lines.clone();
    sorted.sort();
    assert_eq!(lines, sorted);
}
