use rustls::KeyLog;
use vefas_core::VefasKeyLog;

#[test]
fn will_log_only_tls13_labels() {
    let kl = VefasKeyLog::new();
    // Required TLS 1.3 labels should be allowed
    for &label in &[
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
        "EXPORTER_SECRET",
    ] {
        assert!(kl.will_log(label), "{} should be allowed", label);
    }

    // Non-standard labels should be rejected after restriction
    assert!(!kl.will_log("CLIENT_EARLY_TRAFFIC_SECRET"));
    assert!(!kl.will_log("SERVER_EARLY_TRAFFIC_SECRET"));
    assert!(!kl.will_log("SOME_OTHER_LABEL"));
}
