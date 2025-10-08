use vefas_core::VefasCoreError;
use vefas_types::errors::{HttpErrorType, TlsErrorType, VefasError};

#[test]
fn maps_core_errors_to_shared_error_taxonomy() {
    let e = VefasCoreError::UrlError("bad url".into());
    let ve: VefasError = e.into();
    match ve {
        VefasError::HttpError { error_type, .. } => {
            assert_eq!(error_type, HttpErrorType::InvalidUrl)
        }
        _ => panic!("unexpected mapping"),
    }

    let e = VefasCoreError::TlsError("invalid handshake".into());
    let ve: VefasError = e.into();
    match ve {
        VefasError::TlsError { error_type, .. } => {
            assert_eq!(error_type, TlsErrorType::InvalidHandshake)
        }
        _ => panic!("unexpected mapping"),
    }
}
