mod common;

use std::fs;
use std::path::Path;

use pgpmanager::utils::check_valid_cert::{check_certificate, CertificateType};

#[test]
fn recognizes_secret_key_as_cert() {
    let dir = tempfile::tempdir().unwrap();
    let (sk_path, _, _) =
        common::generate_test_keypair(dir.path(), "CertChk <certchk@test.invalid>", "pass123");

    assert!(
        matches!(
            check_certificate(Path::new(&sk_path)),
            CertificateType::Cert(_)
        ),
        "secret key should be recognized as CertificateType::Cert"
    );
}

#[test]
fn recognizes_public_cert_as_cert() {
    let dir = tempfile::tempdir().unwrap();
    let (_, pub_path, _) =
        common::generate_test_keypair(dir.path(), "PubChk <pubchk@test.invalid>", "pass123");

    assert!(
        matches!(
            check_certificate(Path::new(&pub_path)),
            CertificateType::Cert(_)
        ),
        "public cert should be recognized as CertificateType::Cert"
    );
}

#[test]
fn recognizes_revocation_as_signature() {
    let dir = tempfile::tempdir().unwrap();
    let (_, _, rev_path) =
        common::generate_test_keypair(dir.path(), "SigChk <sigchk@test.invalid>", "pass123");

    assert!(
        matches!(
            check_certificate(Path::new(&rev_path)),
            CertificateType::Sig(_)
        ),
        "revocation cert should be recognized as CertificateType::Sig"
    );
}

#[test]
fn rejects_invalid_file() {
    let dir = tempfile::tempdir().unwrap();
    let invalid_path = dir.path().join("invalid.pgp");
    fs::write(&invalid_path, b"this is not a PGP file").unwrap();

    assert!(
        matches!(check_certificate(&invalid_path), CertificateType::Invalid),
        "garbage data should be recognized as Invalid"
    );
}

#[test]
fn rejects_nonexistent_file() {
    assert!(
        matches!(
            check_certificate(Path::new("/nonexistent/path/file.pgp")),
            CertificateType::Invalid
        ),
        "non-existent file should be recognized as Invalid"
    );
}

#[test]
fn rejects_empty_file() {
    let dir = tempfile::tempdir().unwrap();
    let empty_path = dir.path().join("empty.pgp");
    fs::write(&empty_path, b"").unwrap();

    assert!(
        matches!(check_certificate(&empty_path), CertificateType::Invalid),
        "empty file should be recognized as Invalid"
    );
}
