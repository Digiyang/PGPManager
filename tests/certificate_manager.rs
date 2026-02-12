mod common;

use std::fs;
use std::path::Path;

use pgpmanager::sequoia_openpgp::certificate_manager::CertificateManager;
use pgpmanager::utils::create_directory::init_directory;
use sequoia_openpgp::crypto::Password;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::types::RevocationStatus;

fn manager() -> CertificateManager {
    CertificateManager
}

/// Helper to compute the paths that `generate_keypair` writes to in ~/.pgpman/.
fn pgpman_paths(uid: &str) -> (String, String, String) {
    let home = home::home_dir().unwrap();
    (
        format!("{}/.pgpman/secrets/{}.pgp", home.display(), uid).replace(' ', ""),
        format!("{}/.pgpman/revocation/{}.rev", home.display(), uid).replace(' ', ""),
        format!("{}/.pgpman/certificates/{}.pgp", home.display(), uid).replace(' ', ""),
    )
}

// ── Export Certificate ───────────────────────────────────────────────

/// Regression test: export_certificate must strip secret key material.
#[test]
fn export_certificate_strips_secret_key_material() {
    let dir = tempfile::tempdir().unwrap();
    let (sk_path, _, _) =
        common::generate_test_keypair(dir.path(), "ExportTest <export@test.invalid>", "testpass");

    init_directory().unwrap();

    let export_name = "test_export_no_leak_safety.pgp";
    let home = home::home_dir().unwrap();
    let export_path = format!("{}/.pgpman/certificates/{}", home.display(), export_name);

    manager().export_certificate(&sk_path, export_name).unwrap();

    let exported = common::read_cert(&export_path);
    assert!(
        !exported.is_tsk(),
        "CRITICAL: exported certificate must not contain secret key material"
    );

    // User ID should be preserved
    let uid = exported.userids().next().expect("should have a user ID");
    assert_eq!(
        uid.component().email().unwrap().unwrap(),
        "export@test.invalid"
    );

    let _ = fs::remove_file(&export_path);
}

// ── Edit Password ────────────────────────────────────────────────────

#[test]
fn edit_password_changes_password_successfully() {
    let dir = tempfile::tempdir().unwrap();
    let (sk_path, _, _) =
        common::generate_test_keypair(dir.path(), "PwChange <pwchange@test.invalid>", "oldpass");

    manager()
        .edit_password(
            &sk_path,
            &Password::from("oldpass"),
            "newpass".into(),
            "newpass".into(),
        )
        .unwrap();

    let cert = common::read_cert(&sk_path);
    let secret = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .unwrap();
    assert!(
        secret.decrypt_secret(&Password::from("newpass")).is_ok(),
        "new password should decrypt the key"
    );
}

#[test]
fn edit_password_with_wrong_original_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (sk_path, _, _) =
        common::generate_test_keypair(dir.path(), "PwWrong <pwwrong@test.invalid>", "correct");

    let result = manager().edit_password(
        &sk_path,
        &Password::from("wrong"),
        "new".into(),
        "new".into(),
    );
    assert!(result.is_err(), "should fail with wrong original password");
}

// ── Edit Expiration Time ─────────────────────────────────────────────

#[test]
fn edit_expiration_time_sets_validity() {
    let dir = tempfile::tempdir().unwrap();
    let (sk_path, _, _) =
        common::generate_test_keypair(dir.path(), "Expiry <expiry@test.invalid>", "pass123");

    manager()
        .edit_expiration_time(&sk_path, &Password::from("pass123"), "5y".into())
        .unwrap();

    let cert = common::read_cert(&sk_path);
    let p = StandardPolicy::new();
    let vc = cert.with_policy(&p, None).unwrap();
    assert!(
        vc.primary_key().key_validity_period().is_some(),
        "key should have an expiration time after editing"
    );
}

#[test]
fn edit_expiration_time_with_wrong_password_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (sk_path, _, _) =
        common::generate_test_keypair(dir.path(), "ExpWrong <expwrong@test.invalid>", "pass123");

    let result = manager().edit_expiration_time(&sk_path, &Password::from("wrong"), "1y".into());
    assert!(result.is_err(), "should fail with wrong password");
}

// ── Add User ─────────────────────────────────────────────────────────

#[test]
fn add_user_increases_user_count() {
    let dir = tempfile::tempdir().unwrap();
    let (sk_path, _, _) =
        common::generate_test_keypair(dir.path(), "OrigUser <orig@test.invalid>", "pass123");

    let count_before = common::read_cert(&sk_path).userids().count();

    manager()
        .add_user(
            &sk_path,
            &Password::from("pass123"),
            "NewUser <new@test.invalid>".into(),
        )
        .unwrap();

    let cert_after = common::read_cert(&sk_path);
    assert_eq!(
        cert_after.userids().count(),
        count_before + 1,
        "user count should increase by 1"
    );
}

// ── Split Users ──────────────────────────────────────────────────────

/// Note: split_users writes to ~/.pgpman/certificates/. Cleaned up after test.
#[test]
fn split_users_retains_only_selected() {
    let dir = tempfile::tempdir().unwrap();
    let (sk_path, _, _) =
        common::generate_test_keypair(dir.path(), "UserA <usera@test.invalid>", "pass123");

    // Add a second user
    manager()
        .add_user(
            &sk_path,
            &Password::from("pass123"),
            "UserB <userb@test.invalid>".into(),
        )
        .unwrap();
    assert_eq!(common::read_cert(&sk_path).userids().count(), 2);

    init_directory().unwrap();

    let split_name = "test_split_safety.pgp";
    let home = home::home_dir().unwrap();
    let split_path = format!("{}/.pgpman/certificates/{}", home.display(), split_name);

    manager()
        .split_users(&sk_path, split_name, vec!["usera@test.invalid".into()])
        .unwrap();

    let split_cert = common::read_cert(&split_path);
    let emails: Vec<String> = split_cert
        .userids()
        .filter_map(|ua| ua.component().email().ok().flatten().map(|e| e.to_string()))
        .collect();

    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0], "usera@test.invalid");

    let _ = fs::remove_file(&split_path);
}

// ── Revoke Key ───────────────────────────────────────────────────────

#[test]
fn revoke_key_marks_cert_as_revoked() {
    let dir = tempfile::tempdir().unwrap();
    let (sk_path, _, _) =
        common::generate_test_keypair(dir.path(), "Revoke <revoke@test.invalid>", "pass123");

    manager()
        .revoke_key(&sk_path, &Password::from("pass123"), "1")
        .unwrap();

    let cert = common::read_cert(&sk_path);
    let p = StandardPolicy::new();
    assert!(
        matches!(
            cert.revocation_status(&p, None),
            RevocationStatus::Revoked(_)
        ),
        "key should be revoked"
    );
}

// ── Revoke Certificate ───────────────────────────────────────────────

#[test]
fn revoke_certificate_with_matching_rev_cert() {
    let dir = tempfile::tempdir().unwrap();
    let (_, pub_path, rev_path) =
        common::generate_test_keypair(dir.path(), "RevCert <revcert@test.invalid>", "pass123");

    manager().revoke_certificate(&pub_path, &rev_path).unwrap();

    let cert = common::read_cert(&pub_path);
    let p = StandardPolicy::new();
    assert!(
        matches!(
            cert.revocation_status(&p, None),
            RevocationStatus::Revoked(_)
        ),
        "certificate should be revoked"
    );
}

// ── Generate Keypair ─────────────────────────────────────────────────

/// Note: generate_keypair writes to ~/.pgpman/. Cleaned up after test.
#[test]
fn generate_keypair_creates_all_files_and_public_cert_has_no_secret() {
    init_directory().unwrap();

    let uid = "GenTest <gentest@test.invalid>";
    let (sk_expected, rev_expected, cert_expected) = pgpman_paths(uid);

    manager()
        .generate_keypair(
            uid.into(),
            "1y".into(),
            "1".into(), // Cv25519 (fastest)
            "genpass".into(),
            "genpass".into(),
        )
        .unwrap();

    assert!(Path::new(&sk_expected).exists(), "secret key should exist");
    assert!(
        Path::new(&rev_expected).exists(),
        "revocation cert should exist"
    );
    assert!(
        Path::new(&cert_expected).exists(),
        "public cert should exist"
    );

    // The public certificate must NOT contain secret key material
    let pub_cert = common::read_cert(&cert_expected);
    assert!(
        !pub_cert.is_tsk(),
        "CRITICAL: public cert must not be a TSK"
    );

    // The secret key must be a TSK
    let sk = common::read_cert(&sk_expected);
    assert!(sk.is_tsk(), "secret key should be a TSK");

    // Clean up
    let _ = fs::remove_file(&sk_expected);
    let _ = fs::remove_file(&rev_expected);
    let _ = fs::remove_file(&cert_expected);
}

#[test]
fn generate_keypair_mismatched_passwords_fails() {
    let result = manager().generate_keypair(
        "MismatchPw <mismatch@test.invalid>".into(),
        "1y".into(),
        "1".into(),
        "pass1".into(),
        "pass2".into(),
    );
    assert!(result.is_err(), "mismatched passwords should fail");
}
